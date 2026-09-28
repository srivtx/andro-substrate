//! The shim methods' behaviour: the code that both answers the app and records
//! the observation.
//!
//! Every function here does two things and cannot do only one. That is the
//! point of the whole crate. A shim that answers without recording is a
//! compatibility layer; one that records without answering is a log. The
//! [`ShimCaller::invoke`](crate::dispatch::ShimCaller::invoke) path is the only
//! way in, and this module is where both halves live.
//!
//! Each handler is selected by the `Behaviour` in
//! [`crate::registry`], so a method in the table with no handler is a
//! `match` that falls through to an error rather than a call that silently does
//! nothing.
//!
//! # The `this` argument
//!
//! Per the trait contract, `args[0]` is the receiver for an instance method and
//! is absent for a static one. The `recv` helpers below make that explicit, and
//! `arg*` helpers skip past it, so a handler reads like Java.

use crate::dispatch::{default_for, Shim, Value};
use crate::error::{ShimError, VfsError};
use crate::event::{axis_value_suffix, Detail, FsOp, Group, Source, SubstrateEvent, Tier};
use crate::policy::NetworkMode;
use crate::redact::{HeaderNames, HttpMethod, RequestMeta};
use crate::system::{self, PackageQuery, PropValue};
use crate::taxonomy::AssumptionId;
use crate::vfs::VPath;

// ------------------------------------------------------------------ arguments

/// The receiver of an instance call, or `None` for a static one.
fn recv(args: &[Value]) -> Option<u32> {
    args.first().and_then(|v| v.as_ref_id())
}

/// The receiver, or an error if the caller promised one and did not deliver.
fn need_recv(args: &[Value]) -> Result<u32, ShimError> {
    recv(args).ok_or_else(|| ShimError::Encode("instance method called without a receiver".into()))
}

/// The `i`-th declared parameter. `params` has the receiver already stripped, so
/// the index is the parameter's own position in the prototype and a static and
/// an instance method with the same prototype are indexed identically.
fn arg(params: &[Value], i: usize) -> Result<&Value, ShimError> {
    params.get(i).ok_or_else(|| {
        ShimError::Encode(format!(
            "shim method received {} parameters, needed {}",
            params.len(),
            i + 1
        ))
    })
}

fn arg_str(params: &[Value], i: usize) -> Result<&str, ShimError> {
    arg(params, i)?
        .as_str()
        .ok_or_else(|| ShimError::Encode(format!("parameter {i} was not a string")))
}

fn arg_int(params: &[Value], i: usize) -> Result<i32, ShimError> {
    arg(params, i)?
        .as_int()
        .ok_or_else(|| ShimError::Encode(format!("parameter {i} was not an int")))
}

// ------------------------------------------------------------------ behaviours

impl Shim {
    /// After a constructor, set up whatever state the class needs.
    pub(crate) fn after_construct(&mut self, class: &str, v: &Value, params: &[Value]) {
        let id = match v.as_ref_id() {
            Some(i) => i,
            None => return,
        };
        match class {
            "Ljava/net/URL;" => {
                if let Ok(s) = arg_str(params, 0) {
                    // A URL is parsed at construction, so a malformed one is a
                    // `MalformedURLException` on a device and is here too. Only
                    // the parsed parts are stored; the raw text, which may carry
                    // a query string, is dropped.
                    if let Ok(meta) = RequestMeta::parse(s) {
                        if let Some(st) = self.objects.get_mut(&id) {
                            st.url_meta = Some(meta);
                        }
                    }
                }
            }
            "Landroid/content/Intent;" => {
                if let Some(st) = self.objects.get_mut(&id) {
                    st.intent.clear();
                }
                if let Ok(action) = arg_str(params, 0) {
                    if let Some(st) = self.objects.get_mut(&id) {
                        st.intent
                            .insert("action".to_string(), Value::Str(action.to_string()));
                    }
                }
            }
            "Landroid/os/Parcel;" => {
                if let Some(st) = self.objects.get_mut(&id) {
                    st.parcel.clear();
                }
            }
            "Landroid/app/Activity;" | "Landroid/app/Application;" => {
                if let Some(st) = self.objects.get_mut(&id) {
                    st.view = Some(crate::layout::View::group(
                        "root",
                        "LinearLayout",
                        crate::layout::NodeKind::LinearLayout,
                        crate::layout::Orientation::Vertical,
                    ));
                }
            }
            "Ljava/io/File;" => {
                if let Ok(s) = arg_str(params, 0) {
                    if let Ok(p) = VPath::parse(s) {
                        if let Some(st) = self.objects.get_mut(&id) {
                            st.path = Some(p);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// A field getter or setter. Records the field *name*, never the value.
    pub(crate) fn field_access(
        &mut self,
        class: &str,
        name: &str,
        is_get: bool,
        recv_args: &[Value],
        params: &[Value],
    ) -> Result<Value, ShimError> {
        if class == "Landroid/os/Build;" || class == "Landroid/os/Build$VERSION;" {
            // `identity = refusing` removed the class from the shim's table in
            // `Shim::with_policy`, so this is the ordinary loader answering and
            // the app sees an ordinary `NoClassDefFoundError`. The *probe* is
            // still recorded first: which field the app went after is the
            // measurement, and it does not depend on getting an answer.
            if !self.loader.resolve(class).0.is_served_by_shim() {
                let _ = system::read_build_field(name, &self.build, self.substrate_policy.identity);
                self.record(system::build_field_event(
                    name,
                    &PropValue::Absent,
                    self.substrate_policy.identity,
                    0,
                    self.virtual_ms(),
                ));
                return Err(self.identity_refusal(class));
            }
            let field = if is_get {
                name.to_string()
            } else {
                name.trim_end_matches("Set").to_string()
            };
            let identity = self.substrate_policy.identity;
            let (value, _) = system::read_build_field(&field, &self.build, identity);
            self.record(system::build_field_event(
                &field,
                &value,
                identity,
                0,
                self.virtual_ms(),
            ));
            return Ok(match value {
                PropValue::Text(t) => Value::Str(t),
                PropValue::Absent => Value::Null,
            });
        }
        if class == "Landroid/os/SystemClock;" {
            let virtual_ms = self.virtual_ms();
            let now = self.now_ms();
            let ev = self.simple_probe(
                "SIGNAL_PAT.CLOCK_MONOTONIC",
                Some(AssumptionId::TimeMonotonic),
                system::clock_detail("SystemClock", virtual_ms, now),
            );
            self.record(ev);
            return Ok(Value::Long(now as i64));
        }
        if class == "Ljava/lang/System;" && name == "currentTimeMillis" {
            // Zero, not the host clock, unless the `time` axis says otherwise —
            // and the axis states which it is. A substrate that returned the
            // host's time would make a recording unreproducible and would leak
            // the host's clock skew into the app; a substrate that is *measured*
            // leaking it is a different and more useful artefact.
            let virtual_ms = self.virtual_ms();
            let wall = self.wall_ms();
            self.record(SubstrateEvent {
                seq: 0,
                t_mono_ms: virtual_ms,
                group: Group::Probes,
                source: Source::SubstrateInstrumentation,
                tier: Tier::T0Direct,
                assumption: Some(AssumptionId::TimeMonotonic),
                detail: Detail::Probes {
                    pattern: "SIGNAL_PAT.CLOCK_WALL",
                    detail: system::wall_clock_detail(virtual_ms, wall),
                    axis: Some(crate::policy::Axis::Time),
                },
            });
            return Ok(Value::Long(wall as i64));
        }
        // No receiver means an `sget`: a static field read, which is how an app
        // reads `Build.FINGERPRINT` and every `static final` constant. There is
        // no Dalvik method behind it, so it gets its own path and its own
        // observation, because on a device this read leaves no trace at all.
        let Some(id) = recv(recv_args) else {
            let v = static_field_value(class, name).unwrap_or(Value::Null);
            let ev = self.field_probe(
                "SIGNAL_PAT.STATIC_FIELD",
                &format!("{class}.{name}"),
                "read by sget; the value is a compile-time constant and is not recorded",
            );
            self.record(ev);
            return Ok(v);
        };
        let key = format!("{class}.{name}");
        if is_get {
            if let Some(st) = self.objects.get(&id) {
                if let Some(v) = st.intent.get(name) {
                    return Ok(v.clone());
                }
                if let Some(p) = st.path.as_ref() {
                    if name == "getAbsolutePath" {
                        return Ok(Value::Str(p.as_str().to_string()));
                    }
                }
                if let Some(u) = st.url_meta.as_ref() {
                    return Ok(match name {
                        "toString" => Value::Str(u.to_string()),
                        "getProtocol" => Value::Str(u.scheme.as_str().to_string()),
                        "getHost" => Value::Str(u.host.clone()),
                        "getPort" => Value::Int(i32::from(u.port)),
                        "getPath" => Value::Str(u.path.clone()),
                        // The raw query string. Never recorded: this is the exact
                        // field the whole redaction layer exists for, and it is
                        // returned to the *app* without being written down.
                        "getQuery" => Value::Str(String::new()),
                        _ => Value::Null,
                    });
                }
            }
            self.record(self.field_probe(
                "SIGNAL_PAT.FIELD_READ",
                &key,
                "the value is not recorded",
            ));
            return Ok(Value::Null);
        }
        let value = arg(params, 0).cloned().unwrap_or(Value::Null);
        if let Some(st) = self.objects.get_mut(&id) {
            st.intent.insert(name.to_string(), value);
        }
        self.record(self.field_probe("SIGNAL_PAT.FIELD_WRITE", &key, "the value is not recorded"));
        Ok(Value::Null)
    }

    fn field_probe(&self, pattern: &'static str, key: &str, note: &str) -> SubstrateEvent {
        SubstrateEvent {
            seq: 0,
            t_mono_ms: self.virtual_ms(),
            group: Group::Probes,
            source: Source::SubstrateInstrumentation,
            tier: Tier::T0Direct,
            assumption: Some(AssumptionId::FwSerialization),
            detail: Detail::Probes {
                pattern,
                detail: format!("{key} {note}"),
                // A field the shim does not fabricate: the app's own state.
                axis: None,
            },
        }
    }

    /// The failure an app sees when the `identity` axis is `refusing` and it
    /// reads `Build.*`.
    ///
    /// Built through the ordinary throw path so it is recorded like every other
    /// exception, and worded so the recording itself says the classloader — not
    /// a policy check in a shim method — is what refused.
    fn identity_refusal(&mut self, class: &str) -> ShimError {
        let identity = self.substrate_policy.identity;
        self.throw(
            "java.lang.NoClassDefFoundError",
            &format!(
                "{class} is not in the shim's class table: the substrate's identity axis is \
                 refusing, so the app reached a field it cannot load. The refusal is the \
                 substrate's choice{}.",
                axis_value_suffix(crate::policy::Axis::Identity, identity.as_str())
            ),
            vec!["android.os.Build".to_string()],
            false,
        )
    }

    fn simple_probe(
        &self,
        pattern: &'static str,
        assumption: Option<AssumptionId>,
        detail: String,
    ) -> SubstrateEvent {
        self.axis_probe(pattern, assumption, detail, None)
    }

    /// A `probes` event that names the substrate-policy axis which produced the
    /// answer in its detail. Every fabricated value in the crate goes through
    /// this, so "which axis answered this" is answerable for all of them and not
    /// only for the ones somebody remembered to label.
    fn axis_probe(
        &self,
        pattern: &'static str,
        assumption: Option<AssumptionId>,
        detail: String,
        axis: Option<crate::policy::Axis>,
    ) -> SubstrateEvent {
        SubstrateEvent {
            seq: 0,
            t_mono_ms: self.virtual_ms(),
            group: Group::Probes,
            source: Source::SubstrateInstrumentation,
            tier: Tier::T0Direct,
            assumption,
            detail: Detail::Probes {
                pattern,
                detail,
                axis,
            },
        }
    }

    /// A `Behaviour::Probe` method: read a system fact, record it, return it.
    pub(crate) fn probe(
        &mut self,
        class: &str,
        name: &str,
        pattern: &'static str,
        recv_args: &[Value],
        params: &[Value],
    ) -> Result<Value, ShimError> {
        match (class, name) {
            ("Landroid/os/SystemClock;", _) => {
                let virtual_ms = self.virtual_ms();
                let now = self.now_ms();
                let ev = self.axis_probe(
                    pattern,
                    Some(AssumptionId::TimeMonotonic),
                    system::clock_detail("SystemClock", virtual_ms, now),
                    Some(crate::policy::Axis::Time),
                );
                self.record(ev);
                Ok(Value::Long(now as i64))
            }
            ("Ljava/lang/System;", "currentTimeMillis") => {
                let _ = self.field_access(class, name, true, recv_args, params)?;
                Ok(Value::Long(self.wall_ms() as i64))
            }
            ("Landroid/util/Log;", _) | ("Ljava/lang/System;", _) => {
                // The tag is a constant an app chose; the message routinely
                // contains a URL, a user id and a stack fragment.
                let tag = arg(params, 1).ok().and_then(|v| v.as_str()).unwrap_or("");
                let tag = arg(params, 0).ok().and_then(|v| v.as_str()).unwrap_or(tag);
                let ev = self.simple_probe(
                    pattern,
                    None,
                    format!(
                        "{class}.{name}(tag=\"{}\"); message not recorded",
                        tag_trunc(tag)
                    ),
                );
                self.record(ev);
                Ok(Value::Int(0))
            }
            ("Landroid/util/Base64;", "encodeToString") => {
                let len = arg(params, 0).ok().and_then(|v| v.byte_len()).unwrap_or(0);
                let ev = self.simple_probe(
                    pattern,
                    None,
                    format!("Base64.encodeToString over {len} bytes; bytes not recorded"),
                );
                self.record(ev);
                Ok(Value::Str(String::new()))
            }
            ("Landroid/widget/Toast;", "makeText") => {
                let len = arg(params, 1).ok().and_then(|v| v.byte_len()).unwrap_or(0);
                let ev = self.simple_probe(
                    pattern,
                    None,
                    format!("Toast.makeText over a {len}-byte message; message not recorded"),
                );
                self.record(ev);
                Ok(self.ref_for(class))
            }
            ("Landroid/webkit/WebView;", "loadUrl") => {
                let url = arg_str(params, 0).unwrap_or("");
                // A WebView load is a network request and is routed to the same
                // sink as an HttpURLConnection, so the two are indistinguishable
                // in the trace — which is right, because the substrate denies
                // both and the study should see one mechanism.
                match RequestMeta::parse(url) {
                    Ok(meta) => {
                        // Recorded twice on purpose: once as a `net` attempt, so a
                        // WebView load is comparable with any other request, and
                        // once as a `probes` entry, so a study can tell a WebView
                        // load from an HttpURLConnection request. SUB.FW.WEBVIEW is
                        // a whole family, and merging the two would make the
                        // measurement a mixture.
                        //
                        // The sentence names the `network` axis's value, because
                        // "the request is denied" and "the app is shown a
                        // response" are the whole difference and the recording has
                        // to say which one happened.
                        let what_happened = match self.substrate_policy.network {
                            NetworkMode::RecordAndDeny => {
                                "the request is denied at the egress \
sink, so the page never loads"
                            }
                            NetworkMode::SyntheticLoopback => {
                                "the request is refused at the \
egress sink and a response is then synthesised and shown to the app, so the page 'loads' \
without a byte having moved"
                            }
                        };
                        let ev = self.axis_probe(
                            pattern,
                            Some(AssumptionId::FwWebview),
                            format!(
                                "WebView.loadUrl to {}:{} -> {what_happened}. The hybrid app \
                                 loses its entire UI, which is SUB.FW.WEBVIEW{}",
                                meta.host,
                                meta.path_under(self.policy.path),
                                axis_value_suffix(
                                    crate::policy::Axis::Network,
                                    self.substrate_policy.network.as_str()
                                )
                            ),
                            Some(crate::policy::Axis::Network),
                        );
                        self.record(ev);
                        let _ = self.egress(meta, HttpMethod::Get, None);
                        Ok(Value::Null)
                    }
                    Err(_e) => Err(self.throw(
                        "java.net.MalformedURLException",
                        "the WebView was given a URL the substrate cannot parse",
                        vec![format!("{class}.{name}")],
                        false,
                    )),
                }
                .map_err(|e: ShimError| e)
            }
            ("Landroid/webkit/WebView;", "addJavascriptInterface") => {
                let name = arg_str(params, 1).unwrap_or("");
                let ev = self.simple_probe(
                    pattern,
                    Some(AssumptionId::FwWebview),
                    format!(
                        "addJavascriptInterface(\"{}\"); the exposed method set is not recorded",
                        tag_trunc(name)
                    ),
                );
                self.record(ev);
                Ok(Value::Null)
            }
            _ => {
                let ev = self.simple_probe(pattern, None, format!("{class}.{name}()"));
                self.record(ev);
                Ok(default_for("V"))
            }
        }
    }

    /// A `Behaviour::Dispatch` method.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn dispatch(
        &mut self,
        class: &str,
        name: &str,
        key: &str,
        recv_args: &[Value],
        params: &[Value],
    ) -> Result<Value, ShimError> {
        match key {
            // ------------------------------------------------ lifecycle
            "activity.onCreate"
            | "activity.onStart"
            | "activity.onResume"
            | "activity.onPause"
            | "activity.onStop"
            | "activity.onDestroy"
            | "application.onCreate" => {
                let stage = key.rsplit('.').next().unwrap_or("onCreate");
                let ev = self.simple_probe(
                    "SIGNAL_PAT.LIFECYCLE",
                    Some(AssumptionId::FwClassLoader),
                    format!("{class}.{stage}() called, in the documented order"),
                );
                self.record(ev);
                Ok(Value::Null)
            }
            "activity.setContentView" | "window.setContentView" => {
                let id = arg_int(params, 0).unwrap_or(0);
                let ev = self.simple_probe(
                    "SIGNAL_PAT.SET_CONTENT_VIEW",
                    Some(AssumptionId::ResArsc),
                    format!(
                        "{class}.{name}(resource id {id}); the substrate has no resources.arsc, so no layout was inflated and the app's view tree never exists"
                    ),
                );
                self.record(ev);
                Ok(Value::Null)
            }
            "activity.findViewById" => {
                let id = arg_int(params, 0).unwrap_or(0);
                let ev = self.simple_probe(
                    "SIGNAL_PAT.FIND_VIEW_BY_ID",
                    Some(AssumptionId::ResArsc),
                    format!(
                        "findViewById(0x{id:x}) -> null for an id the substrate does not define"
                    ),
                );
                self.record(ev);
                Ok(Value::Null)
            }
            "activity.finish" => {
                let ev = self.simple_probe(
                    "SIGNAL_PAT.INTENT_DISPATCH",
                    Some(AssumptionId::IpcPackageManagerSelf),
                    "finish() requested; no activity manager exists, so no second activity is ever launched"
                        .to_string(),
                );
                self.record(ev);
                Ok(Value::Null)
            }
            "activity.getWindow" => {
                let v = self.ref_for("Landroid/view/Window;");
                Ok(v)
            }
            "receiver.onReceive" => Ok(Value::Null),

            // ------------------------------------------------ context
            "context.getPackageName" => Ok(Value::Str(self.package.clone())),
            "context.getPackageManager" => Ok(self.ref_for("Landroid/content/pm/PackageManager;")),
            "context.getApplicationInfo" => {
                let ev = self.simple_probe(
                    "SIGNAL_PAT.PM_SELF",
                    Some(AssumptionId::IpcPackageManagerSelf),
                    format!(
                        "getApplicationInfo() for {}; sourceDir names a path the substrate does not mount, so a direct APK read fails (SUB.FS.PACKAGE_PATH)",
                        self.package
                    ),
                );
                self.record(ev);
                Ok(self.ref_for("Landroid/content/pm/ApplicationInfo;"))
            }
            "context.getSystemService" => {
                let svc = arg_str(params, 0).unwrap_or("");
                // Every service except the package manager is null. That is
                // SUB.IPC.SYSTEM_SERVICE's whole content, and the *name the app
                // asked for* is the measurement, not the null.
                let is_pm = svc == "package";
                let ev = self.simple_probe(
                    "SIGNAL_PAT.SYSTEM_SERVICE",
                    Some(AssumptionId::IpcSystemService),
                    format!(
                        "getSystemService(\"{}\") -> {}",
                        tag_trunc(svc),
                        if is_pm {
                            "the shim PackageManager"
                        } else {
                            "null"
                        }
                    ),
                );
                self.record(ev);
                if is_pm {
                    return Ok(self.ref_for("Landroid/content/pm/PackageManager;"));
                }
                Ok(Value::Null)
            }
            "context.getFilesDir" | "context.getCacheDir" | "context.getDataDir" => {
                let leaf = match key {
                    "context.getCacheDir" => "cache",
                    "context.getDataDir" => "",
                    _ => "files",
                };
                let p = if leaf.is_empty() {
                    self.data_dir.clone()
                } else {
                    self.data_dir.join(leaf)
                };
                if !self.vfs.exists(&p) {
                    let _ = self.vfs.mkdir(&p.parent());
                    let _ = self.vfs.mkdir(&p);
                }
                self.vfs_op(FsOp::Stat, &p, 0, Ok(0));
                Ok(Value::Str(p.as_str().to_string()))
            }
            "context.getExternalFilesDir" => {
                let p = VPath::parse("/sdcard/Android/data")?;
                self.vfs_op(FsOp::Stat, &p, 0, Ok(0));
                let ev = self.simple_probe(
                    "SIGNAL_PAT.EXTERNAL_STORAGE",
                    Some(AssumptionId::FsSystemLayout),
                    "getExternalFilesDir -> /sdcard/Android/data; the directory exists and is empty, so SUB.FS.EXTERNAL_STORAGE degrades rather than fails"
                        .to_string(),
                );
                self.record(ev);
                Ok(Value::Str(p.as_str().to_string()))
            }
            "context.startActivity" | "context.startService" | "context.sendBroadcast" => {
                let what = key.trim_start_matches("context.");
                let ev = self.simple_probe(
                    "SIGNAL_PAT.INTENT_DISPATCH",
                    Some(if what == "sendBroadcast" {
                        AssumptionId::FwSerialization
                    } else {
                        AssumptionId::IpcPackageManagerSelf
                    }),
                    format!(
                        "{what} requested; delivered to nothing (one process, no activity manager, no system broadcasts)"
                    ),
                );
                self.record(ev);
                Ok(Value::Null)
            }
            "context.registerReceiver" => {
                let ev = self.simple_probe(
                    "SIGNAL_PAT.RECEIVER_REGISTERED",
                    Some(AssumptionId::FwClassLoader),
                    "registerReceiver: registered, and no system broadcast will ever be delivered (SUB.PWR.BOOT_COMPLETED is structurally unsatisfiable)"
                        .to_string(),
                );
                self.record(ev);
                Ok(Value::Null)
            }
            "res.getString" => {
                let id = arg_int(params, 0).unwrap_or(0);
                let ev = self.simple_probe(
                    "SIGNAL_PAT.RESOURCE_LOOKUP",
                    Some(AssumptionId::ResArsc),
                    format!("getString(0x{id:x}) -> null; no resources.arsc and no name-to-id map"),
                );
                self.record(ev);
                Ok(Value::Null)
            }
            "res.getIdentifier" => {
                let ev = self.simple_probe(
                    "SIGNAL_PAT.RESOURCE_LOOKUP",
                    Some(AssumptionId::ResArsc),
                    format!(
                        "getIdentifier(\"{}\", \"{}\", \"{}\") -> 0. SUB.RES.PACKAGE_RESOLVER needs \
the name-to-id mapping, and returning an id without one is the silent-wrong-resource bug the \
taxonomy warns about, so the shim returns 0 and says so",
                        tag_trunc(arg_str(params, 0).unwrap_or("")),
                        tag_trunc(arg_str(params, 1).unwrap_or("")),
                        tag_trunc(arg_str(params, 2).unwrap_or(""))
                    ),
                );
                self.record(ev);
                Ok(Value::Int(0))
            }
            "res.getDisplayMetrics" => {
                let dm = self.ref_for("Landroid/util/DisplayMetrics;");
                let ev = self.simple_probe(
                    "SIGNAL_PAT.DISPLAY_METRICS",
                    Some(AssumptionId::BuildAbilities),
                    "getDisplayMetrics(): synthetic density and size. Every dp-to-pixel decision \
an app makes is therefore unfounded, which is SUB.RES.DISPLAY_METRICS"
                        .to_string(),
                );
                self.record(ev);
                Ok(dm)
            }
            "res.assetsOpen" => {
                let ev = self.simple_probe(
                    "SIGNAL_PAT.RESOURCE_LOOKUP",
                    Some(AssumptionId::ResArsc),
                    format!(
                        "AssetManager.{}(\"{}\") -> empty. The APK is not a filesystem, so there is \
nothing to open; the attempt is recorded because the attempt is the finding",
                        name,
                        tag_trunc(arg_str(params, 0).unwrap_or(""))
                    ),
                );
                self.record(ev);
                if name == "open" {
                    return Ok(Value::Null);
                }
                Ok(self.ref_for("Ljava/util/ArrayList;"))
            }
            "service.onBind"
            | "service.onStartCommand"
            | "service.onHandleIntent"
            | "job.onStartJob" => {
                let ev = self.simple_probe(
                    "SIGNAL_PAT.SERVICE_LIFECYCLE",
                    Some(AssumptionId::IpcSystemService),
                    format!("{class}.{name} was declared but never called: there is one process and no service manager")
                );
                self.record(ev);
                Ok(if name == "onBind" {
                    Value::Null
                } else {
                    Value::Int(0)
                })
            }
            "service.stopSelf" | "tile.updateTile" => Ok(Value::Null),
            "notification.notify" => {
                let ev = self.simple_probe(
                    "SIGNAL_PAT.NOTIFICATION",
                    Some(AssumptionId::IpcSystemService),
                    "NotificationManager.notify: recorded and dropped. There is no shade, no channel \
registry and no runtime POST_NOTIFICATIONS permission, so the app's whole notification surface is unreachable (SUB.IPC.NOTIFICATION)"
                        .to_string(),
                );
                self.record(ev);
                Ok(Value::Null)
            }
            "notification.areNotificationsEnabled" => {
                let ev = self.simple_probe(
                    "SIGNAL_PAT.NOTIFICATION",
                    Some(AssumptionId::IpcSystemService),
                    "areNotificationsEnabled() -> true. Reporting false would manufacture a refusal \
that has nothing to do with the app's code."
                        .to_string(),
                );
                self.record(ev);
                Ok(Value::Int(1))
            }
            "ime.onCreateInputView" | "ime.onEvaluateFullscreenMode" | "ime.commitText" => {
                let ev = self.simple_probe(
                    "SIGNAL_PAT.IME",
                    Some(AssumptionId::IpcSystemService),
                    format!(
                        "{class}.{name}: never called. The substrate has no window manager, so no \
soft keyboard is ever shown and no field can receive text. An app that gates its whole login \
on an IME produces nothing and reports nothing (SUB.INPUT.IME)"
                    ),
                );
                self.record(ev);
                Ok(if name == "commitText" || name == "deleteSurroundingText" {
                    Value::Int(0)
                } else {
                    Value::Null
                })
            }
            "alarm.set" | "alarm.cancel" => {
                let verb = if name == "cancel" {
                    "cancelled"
                } else {
                    "enqueued"
                };
                let ev = self.simple_probe(
                    "SIGNAL_PAT.ALARM",
                    Some(AssumptionId::IpcSystemService),
                    format!(
                        "{class}.{name} {verb}. It will never fire: a substrate has no alarm daemon, \
no Doze and no process reaping, so deferred work never runs (SUB.IPC.ALARM_MANAGER)"
                    ),
                );
                self.record(ev);
                Ok(Value::Null)
            }
            "job.schedule" => {
                let ev = self.simple_probe(
                    "SIGNAL_PAT.JOB_SCHEDULER",
                    Some(AssumptionId::IpcSystemService),
                    "JobScheduler.schedule accepted the job and will never run it. The app gets no \
error and no visible symptom at all, which is why the taxonomy lists this family"
                        .to_string(),
                );
                self.record(ev);
                Ok(Value::Int(0))
            }
            "audio.getStreamVolume" | "audio.setStreamVolume" => {
                let ev = self.simple_probe(
                    "SIGNAL_PAT.AUDIO",
                    Some(AssumptionId::BuildAbilities),
                    format!("{class}.{name}: there is no audio hardware, so any volume- or mute-dependent behaviour the app takes is unfounded")
                );
                self.record(ev);
                Ok(if name == "getStreamVolume" {
                    Value::Int(0)
                } else {
                    Value::Null
                })
            }
            "power.newWakeLock" | "power.acquire" => {
                let ev = self.simple_probe(
                    "SIGNAL_PAT.WAKE_LOCK",
                    Some(AssumptionId::TimeVsync),
                    format!(
                        "{class}.{name}: granted, and irrelevant. Nothing is ever reaped in a \
substrate, so holding a wake lock changes nothing -- the OPPOSITE of the failure a device \
shows, which is the more confusing direction (SUB.PWR.WAKE_LOCK)"
                    ),
                );
                self.record(ev);
                if name == "newWakeLock" {
                    return Ok(self.ref_for("Landroid/os/PowerManager$WakeLock;"));
                }
                Ok(if name == "isHeld" {
                    Value::Int(0)
                } else {
                    Value::Null
                })
            }
            "power.isScreenOn" => {
                let ev = self.simple_probe(
                    "SIGNAL_PAT.SCREEN_STATE",
                    Some(AssumptionId::BuildAbilities),
                    "PowerManager.isScreenOn() -> false. There is no display, so keep-screen-on is a \
no-op and every screen-state-dependent behaviour is unfounded (SUB.GFX.SCREEN_ON)"
                        .to_string(),
                );
                self.record(ev);
                Ok(Value::Int(0))
            }
            "power.isIgnoringBatteryOptimizations" => {
                let ev = self.simple_probe(
                    "SIGNAL_PAT.BATTERY",
                    Some(AssumptionId::BuildAbilities),
                    "isIgnoringBatteryOptimizations() -> true: nothing is ever optimised away here, \
so a background-sync deferral path never engages (SUB.PWR.DOZE)"
                        .to_string(),
                );
                self.record(ev);
                Ok(Value::Int(1))
            }
            "res.getAssets" | "inflater.from" => {
                let ev = self.simple_probe(
                    "SIGNAL_PAT.RESOURCE_LOOKUP",
                    Some(AssumptionId::ResArsc),
                    format!("{class}.{name}(): the APK is not a filesystem, so there is nothing to inflate or open")
                );
                self.record(ev);
                Ok(self.ref_for(class))
            }

            // ------------------------------------------------ package manager
            "pm.getPackageInfo" | "pm.getApplicationInfo" => {
                let pkg = arg_str(params, 0).unwrap_or("");
                let mode = self.substrate_policy.cross_app_packages;
                let q = PackageQuery::ask(pkg, &self.package, mode);
                let ev = q.event(0, self.virtual_ms());
                self.record(ev);
                // The query is recorded before the throw, on purpose: under
                // `cross_app_packages = error` the app asked a question and the
                // substrate refused to answer it, and both halves are the
                // finding.
                if q.throws() {
                    return Err(self.throw(
                        "android.content.pm.NameNotFoundException",
                        &format!(
                            "the substrate's cross-app package axis is refusing, so the query about \
                             {} was not answered{}",
                            pkg,
                            axis_value_suffix(crate::policy::Axis::CrossAppPackages, mode.as_str())
                        ),
                        vec![format!("{class}.{name}")],
                        false,
                    ));
                }
                if !q.installed {
                    return Ok(Value::Null);
                }
                Ok(self.ref_for(class))
            }
            "pm.getInstalledPackages" | "pm.queryIntentActivities" => {
                let mode = self.substrate_policy.cross_app_packages;
                if mode.cross_app_throws() {
                    let ev = self.axis_probe(
                        "SIGNAL_PAT.PM_QUERY",
                        Some(AssumptionId::IpcPackageManagerOther),
                        system::installed_list_probe(class, name, mode),
                        Some(crate::policy::Axis::CrossAppPackages),
                    );
                    self.record(ev);
                    return Err(self.throw(
                        "android.content.pm.NameNotFoundException",
                        &format!(
                            "the substrate's cross-app package axis is refusing, so {name} was not \
                             answered{}",
                            axis_value_suffix(crate::policy::Axis::CrossAppPackages, mode.as_str())
                        ),
                        vec![format!("{class}.{name}")],
                        false,
                    ));
                }
                let ev = self.axis_probe(
                    "SIGNAL_PAT.PM_QUERY",
                    Some(AssumptionId::IpcPackageManagerOther),
                    system::installed_list_probe(class, name, mode),
                    Some(crate::policy::Axis::CrossAppPackages),
                );
                self.record(ev);
                Ok(self.ref_for("Ljava/util/ArrayList;"))
            }
            "pm.hasSystemFeature" => {
                let f = arg_str(params, 0).unwrap_or("");
                let has = self.capabilities.has_system_feature(f);
                let ev = self.simple_probe(
                    "SIGNAL_PAT.SYSTEM_FEATURE",
                    Some(AssumptionId::BuildAbilities),
                    format!("hasSystemFeature(\"{}\") -> {has}", tag_trunc(f)),
                );
                self.record(ev);
                Ok(Value::Int(i32::from(has)))
            }
            "pm.getInstallerPackageName" => {
                let ev = self.simple_probe(
                    "SIGNAL_PAT.PM_QUERY",
                    Some(AssumptionId::IpcPackageManagerOther),
                    "getInstallerPackageName -> null; an APK loaded into a browser was never installed by anything"
                        .to_string(),
                );
                self.record(ev);
                Ok(Value::Null)
            }
            "pm.isDebuggable" => {
                let ev = self.simple_probe(
                    "SIGNAL_PAT.BUILD_TAGS",
                    Some(AssumptionId::BuildTags),
                    "ApplicationInfo.isDebuggable() -> false. Reporting true would manufacture an integrity failure that has nothing to do with the app."
                        .to_string(),
                );
                self.record(ev);
                Ok(Value::Int(0))
            }

            // ------------------------------------------------ bundles
            "bundle.putString" | "bundle.putInt" | "bundle.putBoolean" => {
                let id = need_recv(recv_args)?;
                let key = arg_str(params, 0)?.to_string();
                let value = arg(params, 1).cloned().unwrap_or(Value::Null);
                let len = value.byte_len().unwrap_or(0);
                self.object_mut(id).bundle.insert(key.clone(), value);
                let kind = key.rsplit('.').next().unwrap_or("put");
                let ev = self.simple_probe(
                    "SIGNAL_PAT.BUNDLE_WRITE",
                    Some(AssumptionId::FwSerialization),
                    format!(
                        "Bundle.{kind}(key=\"{}\", {len} bytes); the value is held so the app can read it back and is never recorded",
                        tag_trunc(&key)
                    ),
                );
                self.record(ev);
                Ok(Value::Null)
            }
            "bundle.getString" | "bundle.getInt" | "bundle.getBoolean" | "bundle.containsKey"
            | "bundle.keySet" | "bundle.isEmpty" | "bundle.size" => {
                let id = need_recv(recv_args)?;
                let key = arg_str(params, 0).unwrap_or("").to_string();
                let st = self.objects.get(&id);
                let present = st.map(|s| s.bundle.contains_key(&key)).unwrap_or(false);
                let got = st.and_then(|s| s.bundle.get(&key).cloned());
                let size = st.map(|s| s.bundle.len() as i32).unwrap_or(0);
                let ev = self.simple_probe(
                    "SIGNAL_PAT.BUNDLE_READ",
                    Some(AssumptionId::FwSerialization),
                    format!(
                        "Bundle.{name}(key=\"{}\") -> {}; keys are recorded, values are not",
                        tag_trunc(&key),
                        if present { "present" } else { "absent" }
                    ),
                );
                self.record(ev);
                Ok(match name {
                    "bundle.containsKey" => Value::Int(i32::from(present)),
                    "bundle.isEmpty" => Value::Int(i32::from(size == 0)),
                    "bundle.size" => Value::Int(size),
                    "bundle.keySet" => self.ref_for("Ljava/util/ArrayList;"),
                    _ if present => got.unwrap_or(Value::Null),
                    _ => Value::Null,
                })
            }
            "parcel.writeString" | "parcel.readString" => {
                let id = need_recv(recv_args)?;
                if key.ends_with("writeString") {
                    let value = arg_str(params, 0).unwrap_or("");
                    let len = value.len();
                    self.object_mut(id)
                        .parcel
                        .push(Value::Str(value.to_string()));
                    let ev = self.simple_probe(
                        "SIGNAL_PAT.PARCEL_WRITE",
                        Some(AssumptionId::FwSerialization),
                        format!("Parcel.writeString({len} bytes); the payload is app data and is counted, not recorded")
                    );
                    self.record(ev);
                    Ok(Value::Null)
                } else {
                    let got = self.objects.get_mut(&id).and_then(|s| s.parcel.pop());
                    let ev = self.simple_probe(
                        "SIGNAL_PAT.PARCEL_READ",
                        Some(AssumptionId::FwSerialization),
                        "Parcel.readString(); round-trips within a run and does not survive a process death, which is SUB.FW.SERIALIZATION"
                            .to_string(),
                    );
                    self.record(ev);
                    Ok(got.unwrap_or(Value::Null))
                }
            }
            "parcel.obtain" => Ok(self.ref_for("Landroid/os/Parcel;")),
            "parcel.recycle" => Ok(Value::Null),

            // ------------------------------------------------ handler / looper
            "handler.post"
            | "handler.postDelayed"
            | "handler.removeCallbacks"
            | "handler.getLooper"
            | "looper.getMainLooper"
            | "looper.prepare"
            | "looper.loop"
            | "looper.quit"
            | "queue.size" => {
                let mut verb = "no-op";
                if key == "handler.post" {
                    let now = self.clock.now_ms();
                    self.queue.push((now, now));
                    verb = "posted";
                } else if key == "handler.postDelayed" {
                    let now = self.clock.now_ms();
                    let d = match arg(params, 1) {
                        Ok(Value::Long(v)) => (*v).max(0) as u64,
                        _ => 0,
                    };
                    self.queue.push((now + d, now));
                    verb = "posted with a delay";
                } else if key == "handler.removeCallbacks" {
                    self.queue.clear();
                    verb = "removed every pending message";
                } else if key == "looper.loop" {
                    verb = "loop() returned immediately instead of blocking";
                } else if key == "queue.size" {
                    verb = "queried";
                }
                let depth = self.queue.len();
                let ev = self.simple_probe(
                    "SIGNAL_PAT.MESSAGE_QUEUE",
                    Some(AssumptionId::TimeVsync),
                    format!(
                        "{class}.{name} {verb}; queue depth now {depth}. Nothing drains it: the substrate has no display and therefore no vsync, so a frame-driven app waits forever."
                    ),
                );
                self.record(ev);
                Ok(match key {
                    "queue.size" => Value::Int(depth as i32),
                    "handler.getLooper" | "looper.getMainLooper" => {
                        self.ref_for("Landroid/os/Looper;")
                    }
                    _ => Value::Null,
                })
            }
            "thread.sleep" => {
                // Advancing the virtual clock rather than blocking: a substrate
                // that really slept would be the source of the timing the study
                // is trying to measure. The *virtual* clock, so a `scaled` or
                // `frozen` policy transforms what the app is shown without
                // corrupting the recording's own timeline.
                let d = match arg(params, 0) {
                    Ok(Value::Long(v)) => (*v).max(0) as u64,
                    _ => 0,
                };
                let before = self.virtual_ms();
                self.clock.advance(d);
                let after_virtual = self.virtual_ms();
                let after = self.now_ms();
                let ev = self.axis_probe(
                    "SIGNAL_PAT.SLEEP",
                    Some(AssumptionId::TimeMonotonic),
                    format!(
                        "Thread.sleep({d} ms) advanced the substrate's virtual clock from {before} \
                         to {after_virtual} ms and returned without blocking. The app is shown \
                         {after} ms of elapsed time, which the time axis derived from that{}",
                        axis_value_suffix(
                            crate::policy::Axis::Time,
                            self.substrate_policy.time.as_str()
                        )
                    ),
                    Some(crate::policy::Axis::Time),
                );
                self.record(ev);
                Ok(Value::Null)
            }
            "thread.currentThread" => Ok(self.ref_for("Ljava/lang/Thread;")),

            // ------------------------------------------------ filesystem
            "fs.openFileInput" | "fs.openFileOutput" => {
                let name = arg_str(params, 0)?;
                let _mode = arg_int(params, 1).unwrap_or(0);
                let p = self.data_dir.join("files").join(name);
                let reading = key == "fs.openFileInput";
                let r: Result<u64, ShimError> = if reading {
                    self.read_path(p.as_str()).map(|d| d.len() as u64)
                } else {
                    self.write_path(p.as_str(), b"")
                };
                match r {
                    Ok(_) => Ok(self.ref_for(if key == "fs.openFileInput" {
                        "Ljava/io/FileInputStream;"
                    } else {
                        "Ljava/io/FileOutputStream;"
                    })),
                    Err(_) => Err(self.throw(
                        "java.io.FileNotFoundException",
                        "the substrate's in-memory VFS has no such node",
                        vec![format!("{class}.{name}")],
                        false,
                    )),
                }
            }
            "io.read" => {
                let ev = self.simple_probe(
                    "SIGNAL_PAT.STREAM_READ",
                    Some(AssumptionId::FsDataDir),
                    "InputStream.read; contents not recorded (a file's contents are the payload, and the oracle's file rule is the same)"
                        .to_string(),
                );
                self.record(ev);
                Ok(Value::Int(-1))
            }
            "io.write" => {
                // `write(byte[] b, int off, int len)`: the count is the third
                // parameter, bounded by what the array actually holds. An app
                // that gets this wrong would otherwise have the shim report more
                // bytes than exist.
                let avail = arg(params, 0).ok().and_then(|v| v.byte_len()).unwrap_or(0);
                let off = arg_int(params, 1).unwrap_or(0).max(0) as u64;
                let len = arg_int(params, 2).unwrap_or(0).max(0) as u64;
                let n = len.min(avail.saturating_sub(off));
                // Roll the write into the connection under construction, so the
                // attempt the recording carries states how many bytes the app
                // *tried* to send. Without this, "sent nothing" and "never got
                // far enough to send" would be the same recording.
                if let Some(c) = self
                    .objects
                    .values_mut()
                    .find_map(|s| s.connection.as_mut())
                {
                    c.body_bytes = c.body_bytes.saturating_add(n);
                }
                let ev = self.simple_probe(
                    "SIGNAL_PAT.STREAM_WRITE",
                    Some(AssumptionId::FsDataDir),
                    format!("OutputStream.write of {n} bytes; contents not recorded"),
                );
                self.record(ev);
                Ok(Value::Null)
            }
            "io.close" => Ok(Value::Null),
            "fs.getAbsolutePath" => {
                // The path is a `VPath`, so it is already canonicalised: `..`
                // resolved, an escape refused, control bytes rejected. A
                // non-canonical path in a recording would be a claim about a
                // file the app never named.
                let id = need_recv(recv_args)?;
                match self.objects.get(&id).and_then(|s| s.path.clone()) {
                    Some(p) => Ok(Value::Str(p.as_str().to_string())),
                    None => Ok(Value::Null),
                }
            }
            "fs.exists" | "fs.length" | "fs.isDirectory" => {
                let p = VPath::parse(arg_str(params, 0)?)?;
                let r: Result<u64, VfsError> = self.vfs.stat(&p).map(|n| n.size());
                self.vfs_op(FsOp::Stat, &p, 0, r);
                Ok(match key {
                    "fs.exists" => Value::Int(i32::from(self.vfs.exists(&p))),
                    "fs.length" => {
                        Value::Long(self.vfs.stat(&p).map(|n| n.size()).unwrap_or(0) as i64)
                    }
                    _ => Value::Int(i32::from(self.vfs.is_dir(&p))),
                })
            }
            "fs.list" => {
                let p = VPath::parse(arg_str(params, 0)?)?;
                let n: Result<u64, VfsError> = self.vfs.list(&p).map(|c| c.len() as u64);
                self.vfs_op(FsOp::List, &p, 0, n);
                Ok(self.ref_for("Ljava/util/ArrayList;"))
            }
            "fs.delete" => {
                let p = VPath::parse(arg_str(params, 0)?)?;
                let r = self.vfs.remove(&p);
                self.vfs_op(FsOp::Unlink, &p, 0, r.map(|_| 0));
                Ok(Value::Int(i32::from(r.is_ok())))
            }
            "fs.externalStorage" => {
                let p = VPath::parse("/sdcard")?;
                self.vfs_op(FsOp::Stat, &p, 0, Ok(0));
                Ok(self.ref_for("Ljava/io/File;"))
            }
            "fs.externalStorageState" => Ok(Value::Str("mounted".to_string())),

            // ------------------------------------------------ networking
            "uri.parse" => {
                let s = arg_str(params, 0)?;
                if RequestMeta::parse(s).is_err() {
                    return Ok(Value::Null);
                }
                Ok(self.ref_for("Landroid/net/Uri;"))
            }
            "net.openConnection" => {
                let id = need_recv(recv_args)?;
                let meta = self.objects.get(&id).and_then(|s| s.url_meta.clone());
                if let Some(st) = self.objects.get_mut(&id) {
                    st.connection = Some(crate::dispatch::ConnectionState {
                        meta,
                        ..Default::default()
                    });
                }
                Ok(self.ref_for("Ljava/net/HttpURLConnection;"))
            }
            "net.setRequestProperty" => {
                let name = arg_str(params, 0)?;
                // The value is `params[1]` and is deliberately **not read**. There
                // is no code path that could put it into an event, because
                // `HeaderNames` has no parameter that would accept one.
                let mut probe = HeaderNames::new();
                let accepted = probe.record(name);
                let names = probe.names();
                if let Some(c) = self
                    .objects
                    .values_mut()
                    .find_map(|s| s.connection.as_mut())
                {
                    c.headers.record(name);
                }
                let redacted = probe.redacted_count();
                let ev = self.simple_probe(
                    "SIGNAL_PAT.HEADER_NAME",
                    Some(AssumptionId::NetEgress),
                    format!(
                        "setRequestProperty(\"{}\") -> {}{}; the value is dropped inside the call",
                        tag_trunc(name),
                        if accepted {
                            format!(
                                "name recorded as {:?}",
                                names.first().cloned().unwrap_or_default()
                            )
                        } else {
                            "name rejected as malformed".to_string()
                        },
                        if redacted > 0 {
                            ", value withheld as non-allowlisted"
                        } else {
                            ""
                        }
                    ),
                );
                self.record(ev);
                Ok(Value::Null)
            }
            "net.setRequestMethod" => {
                let m = arg_str(params, 0)?;
                let parsed = HttpMethod::parse(m);
                if let Some(c) = self
                    .objects
                    .values_mut()
                    .find_map(|s| s.connection.as_mut())
                {
                    c.method = parsed;
                }
                Ok(Value::Null)
            }
            "net.setDoOutput" => Ok(Value::Null),
            "net.setConnectTimeout" | "net.setReadTimeout" => {
                let t = arg_int(params, 0).unwrap_or(0).max(0) as u32;
                if let Some(c) = self
                    .objects
                    .values_mut()
                    .find_map(|s| s.connection.as_mut())
                {
                    c.timeout_ms = Some(t);
                }
                Ok(Value::Null)
            }
            "net.connect" | "net.socketConnect" => {
                let (meta, method, body) = self.pending_request();
                match meta {
                    Some(meta) => {
                        let presentation = self.egress(meta.clone(), method, body);
                        // The sink refused. What the app is shown is the
                        // policy's decision, and it cannot change the fact that
                        // the refusal happened: `egress` returns the sink's own
                        // `Err` and `denials` has already been incremented.
                        let _ = presentation;
                        match self.substrate_policy.network.loopback_response() {
                            Some(r) => {
                                let ev = self.axis_probe(
                                    "SIGNAL_PAT.LOOPBACK_RESPONSE",
                                    Some(AssumptionId::NetEgress),
                                    format!(
                                        "connect() returned normally and the app was shown a \
                                         synthesised {} response ({}). Nothing was transmitted: \
                                         the egress sink refused this attempt exactly as it \
                                         refuses every other, and the response is a value this \
                                         policy declared.",
                                        r.status, r.content_type
                                    ),
                                    Some(crate::policy::Axis::Network),
                                );
                                self.record(ev);
                                Ok(Value::Null)
                            }
                            None => Err(self.throw(
                                "java.net.ConnectException",
                                "the substrate denies egress by construction; no socket is opened and no DNS query is made",
                                vec![format!("{class}.{name}")],
                                false,
                            )),
                        }
                    }
                    None => Err(self.throw(
                        "java.net.SocketException",
                        "connect() on a connection with no URL",
                        vec![format!("{class}.{name}")],
                        false,
                    )),
                }
            }
            "net.getResponseCode" => {
                // Under `synthetic_loopback` the app is shown the declared
                // status; otherwise this throws, as it always has.
                if let Some(r) = self.substrate_policy.network.loopback_response() {
                    let ev = self.axis_probe(
                        "SIGNAL_PAT.LOOPBACK_RESPONSE",
                        Some(AssumptionId::NetEgress),
                        format!(
                            "getResponseCode() -> {}: synthesised by the substrate's network axis, \
                             not received. An app that branches on 2xx takes a success branch it \
                             would not have taken on any device this substrate can emulate{}",
                            r.status,
                            axis_value_suffix(
                                crate::policy::Axis::Network,
                                self.substrate_policy.network.as_str()
                            )
                        ),
                        Some(crate::policy::Axis::Network),
                    );
                    self.record(ev);
                    return Ok(Value::Int(i32::from(r.status)));
                }
                Err(self.throw(
                    "java.io.IOException",
                    "no response exists: the substrate never opened a connection",
                    vec![format!("{class}.{name}")],
                    false,
                ))
            }
            "net.getInputStream" => {
                if let Some(r) = self.substrate_policy.network.loopback_response() {
                    let ev = self.axis_probe(
                        "SIGNAL_PAT.LOOPBACK_RESPONSE",
                        Some(AssumptionId::NetEgress),
                        format!(
                            "getInputStream() -> a handle onto {} declared zero bytes. The body is \
                             a zero-filled buffer of exactly that length; it contains no received \
                             data and none is recorded{}",
                            r.declared_body_bytes,
                            axis_value_suffix(
                                crate::policy::Axis::Network,
                                self.substrate_policy.network.as_str()
                            )
                        ),
                        Some(crate::policy::Axis::Network),
                    );
                    self.record(ev);
                    return Ok(self.ref_for("Ljava/io/InputStream;"));
                }
                Err(self.throw(
                    "java.io.IOException",
                    "no response exists: the substrate never opened a connection",
                    vec![format!("{class}.{name}")],
                    false,
                ))
            }
            "net.getOutputStream" => {
                // A sink that counts and discards, so a POST reaches a recorded
                // body length. Without this, "sent 0 bytes" and "never got far
                // enough to send" would be indistinguishable.
                if let Some(c) = self
                    .objects
                    .values_mut()
                    .find_map(|s| s.connection.as_mut())
                {
                    c.body_bytes = 0;
                }
                Ok(self.ref_for("Ljava/io/OutputStream;"))
            }

            // ------------------------------------------------ jni
            "jni.loadLibrary" | "jni.load" => {
                let lib = arg_str(params, 0)?.to_string();
                let sym = format!("Java_{lib}_load");
                let e = self.note_native(&sym, Some("Ljava/lang/System;"), Some(&lib));
                let _ = self.throw(
                    "java.lang.UnsatisfiedLinkError",
                    &format!("no ELF loader in the substrate: {lib} cannot be mapped"),
                    vec![format!("{class}.{name}")],
                    false,
                );
                Err(e)
            }

            // ------------------------------------------------ reflection
            "class.forName" => {
                let n = arg_str(params, 0)?;
                let slashed = n.replace('.', "/");
                let descriptor = if slashed.starts_with('[') {
                    slashed.clone()
                } else {
                    format!("L{slashed};")
                };
                let (resolution, _) = self.note_class_resolution(&descriptor);
                match resolution {
                    crate::event::Resolution::ShimDex
                    | crate::event::Resolution::AppDex
                    | crate::event::Resolution::ShimSupersedesApp => Ok(self.ref_for(&descriptor)),
                    _ => Err(self.throw(
                        "java.lang.ClassNotFoundException",
                        &format!("{n} resolves to nothing in the shim or in any app DEX"),
                        vec!["java.lang.Class.forName".to_string()],
                        false,
                    )),
                }
            }
            "class.getMethod" => {
                let m = arg_str(params, 0)?;
                let ev = self.simple_probe(
                    "SIGNAL_PAT.REFLECTION",
                    Some(AssumptionId::FwClassLoader),
                    format!("getMethod(\"{m}\"); reflective calls are dispatched through the same table as direct ones, so a reflective call and a direct call produce identical observations")
                );
                self.record(ev);
                Ok(self.ref_for("Ljava/lang/reflect/Method;"))
            }
            "method.invoke" => Ok(Value::Null),
            "system.getProperty" => {
                let k = arg_str(params, 0)?;
                // The substrate's own properties first, then the identity axis's
                // answer for a `ro.*` key. The second half is new: a `getprop` is
                // the same assumption as a `Build.*` read and the recording used
                // to record the *answer* (a null) without recording the *question*,
                // which made `ro.kernel.qemu`'s absence indistinguishable from a
                // `getProperty` of a key nobody models.
                if let Some(prop) = crate::system::Prop::parse(k) {
                    let identity = self.substrate_policy.identity;
                    let value = identity.read(prop, &self.build);
                    let ev = system::property_event(k, &value, identity, 0, self.virtual_ms());
                    self.record(ev);
                    return Ok(match value {
                        PropValue::Text(t) => Value::Str(t),
                        PropValue::Absent => Value::Null,
                    });
                }
                Ok(match k {
                    "substrate.runtime" => Value::Str("shim-observation/1".to_string()),
                    "substrate.egress" => Value::Str("denied".to_string()),
                    "substrate.policy" => Value::Str(self.substrate_policy.digest()),
                    _ => Value::Null,
                })
            }

            // ------------------------------------------------ view
            "view.measure" | "view.layout" => Ok(Value::Null),
            "view.setOnClickListener" => {
                let ev = self.simple_probe(
                    "SIGNAL_PAT.CLICK_LISTENER",
                    Some(AssumptionId::FwWebview),
                    "setOnClickListener: the listener is held and will never be invoked; the substrate delivers no input (SUB.INPUT.INPUT_EVENT), so an app that gates work on a tap produces nothing and reports nothing"
                        .to_string(),
                );
                self.record(ev);
                Ok(Value::Null)
            }
            "viewgroup.addView"
            | "viewgroup.removeView"
            | "viewgroup.getChildCount"
            | "viewgroup.getChildAt"
            | "linearlayout.setOrientation"
            | "imageview.setImageResource"
            | "window.addFlags"
            | "textview.setText" => Ok(Value::Null),
            "pattern.compile" | "pattern.matcher" => {
                let p = arg_str(params, 0).unwrap_or("");
                let ev = self.simple_probe(
                    "SIGNAL_PAT.REGEX",
                    Some(AssumptionId::FwClassLoader),
                    format!(
                        "{key}(\"{}\", {} chars); the pattern is reported and not evaluated, because an unevaluated pattern must fail rather than answer wrongly",
                        regex_trunc(p),
                        p.chars().count()
                    )
                );
                self.record(ev);
                Ok(self.ref_for(class))
            }
            other => Err(ShimError::Encode(format!(
                "registry key {other:?} for {class}.{name} has no handler"
            ))),
        }
    }

    /// The connection the shim is currently configuring.
    fn pending_request(&self) -> (Option<RequestMeta>, HttpMethod, Option<u64>) {
        for st in self.objects.values() {
            if let Some(c) = &st.connection {
                if c.meta.is_some() {
                    let body = if c.body_bytes == 0 {
                        None
                    } else {
                        Some(c.body_bytes)
                    };
                    return (c.meta.clone(), c.method, body);
                }
            }
        }
        (None, HttpMethod::Get, None)
    }
}

/// The real values of the `static final` constants the table declares.
///
/// A `static final int` is inlined by `d8` at the call site, so an app's DEX does
/// not even reference the field — which means a device arm cannot observe the
/// read at all, and a substrate that returned `0` would be indistinguishable from
/// one that was asked. Returning the documented platform value keeps the shim
/// honest, and the *read* is recorded even when the app's bytecode never
/// mentioned the field.
fn static_field_value(class: &str, name: &str) -> Option<Value> {
    Some(match (class, name) {
        ("Landroid/os/Build;", "SERIAL") | ("Landroid/os/Build;", "BOOTLOADER") => {
            Value::Str(String::new())
        }
        ("Landroid/content/Intent;", "ACTION_MAIN") => {
            Value::Str("android.intent.action.MAIN".to_string())
        }
        ("Landroid/content/Intent;", "ACTION_VIEW") => {
            Value::Str("android.intent.action.VIEW".to_string())
        }
        ("Landroid/content/pm/ApplicationInfo;", "FLAG_DEBUGGABLE") => Value::Int(0x0002),
        ("Landroid/view/View;", "VISIBLE") => Value::Int(0),
        ("Landroid/view/View;", "INVISIBLE") => Value::Int(4),
        ("Landroid/view/View;", "GONE") => Value::Int(8),
        ("Landroid/view/ViewGroup$LayoutParams;", "MATCH_PARENT") => Value::Int(-1),
        ("Landroid/view/ViewGroup$LayoutParams;", "WRAP_CONTENT") => Value::Int(-2),
        ("Landroid/widget/LinearLayout;", "HORIZONTAL") => Value::Int(0),
        ("Landroid/widget/LinearLayout;", "VERTICAL") => Value::Int(1),
        ("Landroid/substrate/Bridge;", "VERSION") => Value::Int(1),
        _ => return None,
    })
}

/// Cap a recorded string at a length the oracle's fields can hold, and strip
/// the characters that would let a value forge a line in a text log.
fn tag_trunc(s: &str) -> String {
    s.chars()
        .take(64)
        .collect::<String>()
        .replace(['\n', '\r', '\t'], " ")
}

fn regex_trunc(s: &str) -> String {
    s.chars()
        .take(80)
        .collect::<String>()
        .replace(['\n', '\r'], " ")
}
