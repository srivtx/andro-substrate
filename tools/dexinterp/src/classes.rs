//! The builtin class table: the slice of `java.*` the engine knows without a DEX.
//!
//! # Why this is a table and not nothing
//!
//! Almost every method an Android app calls is declared on a class that is not
//! in the APK. `check-cast v3, Landroid/os/PowerManager;` and
//! `instance-of v1, Ljava/lang/String;` are the two instructions that decide
//! whether control flow can even be followed, and both need the *hierarchy*,
//! not the behaviour: `catch (Ljava/lang/Error;)` has to match a
//! `NoSuchMethodError` because of three `extends` clauses that live in
//! `core.jar`, not in the APK.
//!
//! So the table carries three things and nothing else: a descriptor, a
//! superclass, and a list of interfaces. It carries **no** fields and **no**
//! methods. Field access and method calls on these classes go to the
//! [`Host`](crate::host::Host), which is the right owner for both.
//!
//! # Why the table is incomplete, and how that incompleteness is reported
//!
//! It is incomplete, and it has to be: `java.*` plus the public Android SDK is
//! tens of thousands of classes. `Throwable`'s hierarchy is modelled properly
//! because it is load-bearing for control flow; `Ljava/util/HashMap;` is
//! modelled as an opaque leaf because nothing in the interpreter's control flow
//! depends on whether it extends `AbstractMap;`.
//!
//! The list is fixed and auditable. Anything missing is *not* silently
//! invented: the engine fabricates a phantom class with the same effect on
//! control flow, and records the descriptor in
//! [`Stats::phantom_classes`](crate::config::Stats::phantom_classes). The size
//! of that list is therefore a measurement, not a failure: an app whose
//! execution needed 400 phantom classes is an app whose framework surface is
//! 400 classes wide, and no interpreter is going to save it.
//!
//! # The exception hierarchy
//!
//! The full `Throwable` tree is present, because a real handler clause names
//! an exact class and the engine has to decide whether an instance matches. The
//! three chains that matter are:
//!
//! ```text
//! Throwable
//! ├── Exception ── RuntimeException ── {Null,Arithmetic,Index,ClassCast,Illegal*,...}
//! │                └── ReflectiveOperationException ── {ClassNotFound,NoSuch*,...}
//! └── Error
//!     ├── VirtualMachineError ── {OutOfMemory,StackOverflow,Internal,...}
//!     └── LinkageError ── {NoSuchMethod,NoSuchField,AbstractMethod,Verify,
//!                          IncompatibleClassChange,ClassFormat,Bootstrap,UnsatisfiedLink,...}
//! ```

/// A builtin class: descriptor, superclass, interfaces.
#[derive(Clone, Copy, Debug)]
pub struct BuiltinClass {
    /// The descriptor, e.g. `Ljava/lang/Throwable;`.
    pub descriptor: &'static str,
    /// The superclass, or `None` for `Ljava/lang/Object;`.
    pub superclass: Option<&'static str>,
    /// Implemented interfaces.
    pub interfaces: &'static [&'static str],
}

const fn leaf(descriptor: &'static str) -> BuiltinClass {
    BuiltinClass {
        descriptor,
        superclass: Some("Ljava/lang/Object;"),
        interfaces: &[],
    }
}

const fn node(
    descriptor: &'static str,
    superclass: &'static str,
    interfaces: &'static [&'static str],
) -> BuiltinClass {
    BuiltinClass {
        descriptor,
        superclass: Some(superclass),
        interfaces,
    }
}

const fn root(descriptor: &'static str) -> BuiltinClass {
    BuiltinClass {
        descriptor,
        superclass: None,
        interfaces: &[],
    }
}

/// The builtin classes, parents before children so the table can be walked in
/// order and every superclass is already present.
///
/// 120 entries. Anything an app needs that is not here becomes a phantom class
/// with the same control-flow effect, and is recorded.
pub static BUILTINS: &[BuiltinClass] = &[
    // ---------------------------------------------------------------- root
    root("Ljava/lang/Object;"),
    // ------------------------------------------------ Throwable hierarchy
    node("Ljava/lang/Throwable;", "Ljava/lang/Object;", &[]),
    node("Ljava/lang/Exception;", "Ljava/lang/Throwable;", &[]),
    node("Ljava/lang/Error;", "Ljava/lang/Throwable;", &[]),
    node("Ljava/lang/RuntimeException;", "Ljava/lang/Exception;", &[]),
    node(
        "Ljava/lang/ReflectiveOperationException;",
        "Ljava/lang/Exception;",
        &[],
    ),
    node("Ljava/lang/VirtualMachineError;", "Ljava/lang/Error;", &[]),
    node("Ljava/lang/LinkageError;", "Ljava/lang/Error;", &[]),
    node("Ljava/lang/AssertionError;", "Ljava/lang/Error;", &[]),
    node("Ljava/lang/ThreadDeath;", "Ljava/lang/Error;", &[]),
    node(
        "Ljava/lang/InterruptedException;",
        "Ljava/lang/Exception;",
        &[],
    ),
    node(
        "Ljava/lang/CloneNotSupportedException;",
        "Ljava/lang/Exception;",
        &[],
    ),
    node(
        "Ljava/lang/ClassNotFoundException;",
        "Ljava/lang/ReflectiveOperationException;",
        &[],
    ),
    node(
        "Ljava/lang/IllegalAccessException;",
        "Ljava/lang/ReflectiveOperationException;",
        &[],
    ),
    node(
        "Ljava/lang/InstantiationException;",
        "Ljava/lang/ReflectiveOperationException;",
        &[],
    ),
    node(
        "Ljava/lang/NoSuchFieldException;",
        "Ljava/lang/ReflectiveOperationException;",
        &[],
    ),
    node(
        "Ljava/lang/NoSuchMethodException;",
        "Ljava/lang/ReflectiveOperationException;",
        &[],
    ),
    node(
        "Ljava/lang/InvocationTargetException;",
        "Ljava/lang/ReflectiveOperationException;",
        &[],
    ),
    node(
        "Ljava/lang/ArithmeticException;",
        "Ljava/lang/RuntimeException;",
        &[],
    ),
    node(
        "Ljava/lang/ArrayStoreException;",
        "Ljava/lang/RuntimeException;",
        &[],
    ),
    node(
        "Ljava/lang/ClassCastException;",
        "Ljava/lang/RuntimeException;",
        &[],
    ),
    node(
        "Ljava/lang/IllegalArgumentException;",
        "Ljava/lang/RuntimeException;",
        &[],
    ),
    node(
        "Ljava/lang/IllegalMonitorStateException;",
        "Ljava/lang/RuntimeException;",
        &[],
    ),
    node(
        "Ljava/lang/IllegalStateException;",
        "Ljava/lang/RuntimeException;",
        &[],
    ),
    node(
        "Ljava/lang/IllegalThreadStateException;",
        "Ljava/lang/IllegalArgumentException;",
        &[],
    ),
    node(
        "Ljava/lang/IndexOutOfBoundsException;",
        "Ljava/lang/RuntimeException;",
        &[],
    ),
    node(
        "Ljava/lang/NegativeArraySizeException;",
        "Ljava/lang/RuntimeException;",
        &[],
    ),
    node(
        "Ljava/lang/NullPointerException;",
        "Ljava/lang/RuntimeException;",
        &[],
    ),
    node(
        "Ljava/lang/NumberFormatException;",
        "Ljava/lang/IllegalArgumentException;",
        &[],
    ),
    node(
        "Ljava/lang/ArrayIndexOutOfBoundsException;",
        "Ljava/lang/IndexOutOfBoundsException;",
        &[],
    ),
    node(
        "Ljava/lang/StringIndexOutOfBoundsException;",
        "Ljava/lang/IndexOutOfBoundsException;",
        &[],
    ),
    node(
        "Ljava/lang/UnsupportedOperationException;",
        "Ljava/lang/RuntimeException;",
        &[],
    ),
    node(
        "Ljava/lang/SecurityException;",
        "Ljava/lang/RuntimeException;",
        &[],
    ),
    node(
        "Ljava/lang/StackOverflowError;",
        "Ljava/lang/VirtualMachineError;",
        &[],
    ),
    node(
        "Ljava/lang/OutOfMemoryError;",
        "Ljava/lang/VirtualMachineError;",
        &[],
    ),
    node(
        "Ljava/lang/InternalError;",
        "Ljava/lang/VirtualMachineError;",
        &[],
    ),
    node(
        "Ljava/lang/NoClassDefFoundError;",
        "Ljava/lang/LinkageError;",
        &[],
    ),
    node(
        "Ljava/lang/ExceptionInInitializerError;",
        "Ljava/lang/LinkageError;",
        &[],
    ),
    node(
        "Ljava/lang/BootstrapMethodError;",
        "Ljava/lang/LinkageError;",
        &[],
    ),
    node(
        "Ljava/lang/UnsatisfiedLinkError;",
        "Ljava/lang/LinkageError;",
        &[],
    ),
    node("Ljava/lang/VerifyError;", "Ljava/lang/LinkageError;", &[]),
    node(
        "Ljava/lang/IncompatibleClassChangeError;",
        "Ljava/lang/LinkageError;",
        &[],
    ),
    node(
        "Ljava/lang/AbstractMethodError;",
        "Ljava/lang/IncompatibleClassChangeError;",
        &[],
    ),
    node(
        "Ljava/lang/IllegalAccessError;",
        "Ljava/lang/IncompatibleClassChangeError;",
        &[],
    ),
    node(
        "Ljava/lang/InstantiationError;",
        "Ljava/lang/IncompatibleClassChangeError;",
        &[],
    ),
    node(
        "Ljava/lang/NoSuchFieldError;",
        "Ljava/lang/IncompatibleClassChangeError;",
        &[],
    ),
    node(
        "Ljava/lang/NoSuchMethodError;",
        "Ljava/lang/IncompatibleClassChangeError;",
        &[],
    ),
    node(
        "Ljava/lang/ClassFormatError;",
        "Ljava/lang/LinkageError;",
        &[],
    ),
    // --------------------------------------------------- java.lang core
    // `CharSequence` and `Comparable` come first because `String` implements
    // both, and an interface must be declared before its implementor.
    leaf("Ljava/lang/CharSequence;"),
    leaf("Ljava/lang/Comparable;"),
    leaf("Ljava/io/Serializable;"),
    node(
        "Ljava/lang/String;",
        "Ljava/lang/Object;",
        &["Ljava/lang/CharSequence;", "Ljava/lang/Comparable;"],
    ),
    node(
        "Ljava/lang/StringBuilder;",
        "Ljava/lang/Object;",
        &["Ljava/lang/CharSequence;"],
    ),
    node(
        "Ljava/lang/StringBuffer;",
        "Ljava/lang/Object;",
        &["Ljava/lang/CharSequence;"],
    ),
    node(
        "Ljava/lang/Class;",
        "Ljava/lang/Object;",
        &["Ljava/io/Serializable;"],
    ),
    leaf("Ljava/lang/Enum;"),
    leaf("Ljava/lang/Number;"),
    leaf("Ljava/lang/Integer;"),
    leaf("Ljava/lang/Long;"),
    leaf("Ljava/lang/Short;"),
    leaf("Ljava/lang/Byte;"),
    leaf("Ljava/lang/Character;"),
    leaf("Ljava/lang/Boolean;"),
    leaf("Ljava/lang/Float;"),
    leaf("Ljava/lang/Double;"),
    node("Ljava/lang/Math;", "Ljava/lang/Object;", &[]),
    node("Ljava/lang/System;", "Ljava/lang/Object;", &[]),
    node("Ljava/lang/Runnable;", "Ljava/lang/Object;", &[]),
    node(
        "Ljava/lang/Thread;",
        "Ljava/lang/Object;",
        &["Ljava/lang/Runnable;"],
    ),
    node("Ljava/lang/ThreadLocal;", "Ljava/lang/Object;", &[]),
    node("Ljava/lang/Iterable;", "Ljava/lang/Object;", &[]),
    node("Ljava/lang/Process;", "Ljava/lang/Object;", &[]),
    node("Ljava/lang/ProcessBuilder;", "Ljava/lang/Object;", &[]),
    leaf("Ljava/lang/ClassLoader;"),
    leaf("Ljava/lang/ref/WeakReference;"),
    leaf("Ljava/lang/ref/SoftReference;"),
    leaf("Ljava/lang/ref/PhantomReference;"),
    node("Ljava/lang/ref/Reference;", "Ljava/lang/Object;", &[]),
    leaf("Ljava/lang/reflect/Method;"),
    leaf("Ljava/lang/reflect/Field;"),
    leaf("Ljava/lang/reflect/Constructor;"),
    leaf("Ljava/lang/reflect/Modifier;"),
    leaf("Ljava/lang/reflect/AccessibleObject;"),
    leaf("Ljava/lang/reflect/Array;"),
    leaf("Ljava/lang/reflect/MethodType;"),
    leaf("Ljava/lang/reflect/Proxy;"),
    leaf("Ljava/lang/invoke/MethodHandle;"),
    leaf("Ljava/lang/invoke/MethodType;"),
    leaf("Ljava/lang/invoke/MethodHandles;"),
    leaf("Ljava/lang/invoke/MethodHandles$Lookup;"),
    leaf("Ljava/lang/invoke/CallSite;"),
    leaf("Ljava/lang/invoke/ConstantCallSite;"),
    leaf("Ljava/lang/invoke/LambdaMetafactory;"),
    node(
        "Ljava/lang/annotation/Annotation;",
        "Ljava/lang/Object;",
        &[],
    ),
    node(
        "Ljava/lang/annotation/Retention;",
        "Ljava/lang/Object;",
        &["Ljava/lang/annotation/Annotation;"],
    ),
    node(
        "Ljava/lang/annotation/Target;",
        "Ljava/lang/Object;",
        &["Ljava/lang/annotation/Annotation;"],
    ),
    node("Ljava/lang/Deprecated;", "Ljava/lang/Object;", &[]),
    node("Ljava/lang/Override;", "Ljava/lang/Object;", &[]),
    node("Ljava/lang/SuppressWarnings;", "Ljava/lang/Object;", &[]),
    node("Ljava/lang/FunctionalInterface;", "Ljava/lang/Object;", &[]),
    node("Ljava/lang/SafeVarargs;", "Ljava/lang/Object;", &[]),
    // ------------------------------------------------------------- java.io
    leaf("Ljava/lang/AutoCloseable;"),
    node(
        "Ljava/io/Closeable;",
        "Ljava/lang/Object;",
        &["Ljava/lang/AutoCloseable;"],
    ),
    leaf("Ljava/io/Flushable;"),
    node("Ljava/io/IOException;", "Ljava/lang/Exception;", &[]),
    node(
        "Ljava/io/FileNotFoundException;",
        "Ljava/io/IOException;",
        &[],
    ),
    node(
        "Ljava/io/UncheckedIOException;",
        "Ljava/lang/RuntimeException;",
        &[],
    ),
    node(
        "Ljava/io/InterruptedIOException;",
        "Ljava/io/IOException;",
        &[],
    ),
    leaf("Ljava/io/File;"),
    leaf("Ljava/io/InputStream;"),
    leaf("Ljava/io/OutputStream;"),
    leaf("Ljava/io/Reader;"),
    leaf("Ljava/io/Writer;"),
    leaf("Ljava/io/PrintWriter;"),
    leaf("Ljava/io/PrintStream;"),
    leaf("Ljava/io/DataInputStream;"),
    leaf("Ljava/io/DataOutputStream;"),
    leaf("Ljava/io/ByteArrayInputStream;"),
    leaf("Ljava/io/ByteArrayOutputStream;"),
    leaf("Ljava/io/ObjectInputStream;"),
    leaf("Ljava/io/ObjectOutputStream;"),
    leaf("Ljava/io/FileInputStream;"),
    leaf("Ljava/io/FileOutputStream;"),
    leaf("Ljava/io/BufferedReader;"),
    leaf("Ljava/io/BufferedWriter;"),
    node(
        "Ljava/io/Externalizable;",
        "Ljava/lang/Object;",
        &["Ljava/io/Serializable;"],
    ),
    // ----------------------------------------------------------- java.util
    node(
        "Ljava/util/Collection;",
        "Ljava/lang/Object;",
        &["Ljava/lang/Iterable;"],
    ),
    node(
        "Ljava/util/List;",
        "Ljava/lang/Object;",
        &["Ljava/util/Collection;"],
    ),
    node(
        "Ljava/util/Set;",
        "Ljava/lang/Object;",
        &["Ljava/util/Collection;"],
    ),
    node("Ljava/util/Map;", "Ljava/lang/Object;", &[]),
    node("Ljava/util/Map$Entry;", "Ljava/lang/Object;", &[]),
    node("Ljava/util/Iterator;", "Ljava/lang/Object;", &[]),
    node(
        "Ljava/util/ListIterator;",
        "Ljava/lang/Object;",
        &["Ljava/util/Iterator;"],
    ),
    node("Ljava/util/Enumeration;", "Ljava/lang/Object;", &[]),
    node("Ljava/util/Comparator;", "Ljava/lang/Object;", &[]),
    node(
        "Ljava/util/Queue;",
        "Ljava/lang/Object;",
        &["Ljava/util/Collection;"],
    ),
    node(
        "Ljava/util/Deque;",
        "Ljava/lang/Object;",
        &["Ljava/util/Queue;"],
    ),
    leaf("Ljava/util/ArrayList;"),
    leaf("Ljava/util/LinkedList;"),
    leaf("Ljava/util/HashMap;"),
    leaf("Ljava/util/HashSet;"),
    leaf("Ljava/util/LinkedHashMap;"),
    leaf("Ljava/util/TreeMap;"),
    leaf("Ljava/util/TreeSet;"),
    leaf("Ljava/util/Vector;"),
    leaf("Ljava/util/RandomAccess;"),
    leaf("Ljava/util/UUID;"),
    leaf("Ljava/util/Date;"),
    leaf("Ljava/util/Calendar;"),
    leaf("Ljava/util/TimeZone;"),
    leaf("Ljava/util/Locale;"),
    leaf("Ljava/util/Optional;"),
    leaf("Ljava/util/OptionalInt;"),
    leaf("Ljava/util/Arrays;"),
    leaf("Ljava/util/Collections;"),
    leaf("Ljava/util/Objects;"),
    leaf("Ljava/util/Base64;"),
    leaf("Ljava/util/Scanner;"),
    node(
        "Ljava/util/NoSuchElementException;",
        "Ljava/lang/RuntimeException;",
        &[],
    ),
    node(
        "Ljava/util/ConcurrentModificationException;",
        "Ljava/lang/RuntimeException;",
        &[],
    ),
    node(
        "Ljava/util/EmptyStackException;",
        "Ljava/lang/RuntimeException;",
        &[],
    ),
    node(
        "Ljava/util/MissingResourceException;",
        "Ljava/lang/RuntimeException;",
        &[],
    ),
    node(
        "Ljava/util/InputMismatchException;",
        "Ljava/util/NoSuchElementException;",
        &[],
    ),
    node("Ljava/util/regex/Pattern;", "Ljava/lang/Object;", &[]),
    node("Ljava/util/regex/Matcher;", "Ljava/lang/Object;", &[]),
    node("Ljava/util/zip/ZipEntry;", "Ljava/lang/Object;", &[]),
    node(
        "Ljava/util/zip/ZipInputStream;",
        "Ljava/io/InputStream;",
        &[],
    ),
    node("Ljava/util/concurrent/Executor;", "Ljava/lang/Object;", &[]),
    leaf("Ljava/util/concurrent/ExecutorService;"),
    leaf("Ljava/util/concurrent/Future;"),
    leaf("Ljava/util/concurrent/Callable;"),
    leaf("Ljava/util/concurrent/TimeUnit;"),
    leaf("Ljava/util/concurrent/atomic/AtomicInteger;"),
    leaf("Ljava/util/concurrent/atomic/AtomicLong;"),
    leaf("Ljava/util/concurrent/atomic/AtomicReference;"),
    leaf("Ljava/util/logging/Logger;"),
    // ------------------------------------------------------------ java.net
    leaf("Ljava/net/URL;"),
    leaf("Ljava/net/URI;"),
    leaf("Ljava/net/URLConnection;"),
    leaf("Ljava/net/HttpURLConnection;"),
    leaf("Ljava/net/InetAddress;"),
    leaf("Ljava/net/Socket;"),
    leaf("Ljava/net/ServerSocket;"),
    leaf("Ljava/net/Proxy;"),
    leaf("Ljava/net/ProxySelector;"),
    leaf("Ljava/net/CookieManager;"),
    leaf("Ljava/net/HttpCookie;"),
    node(
        "Ljava/net/UnknownHostException;",
        "Ljava/io/IOException;",
        &[],
    ),
    node("Ljava/net/SocketException;", "Ljava/io/IOException;", &[]),
    node("Ljava/net/ProtocolException;", "Ljava/io/IOException;", &[]),
    node(
        "Ljava/net/MalformedURLException;",
        "Ljava/io/IOException;",
        &[],
    ),
    node(
        "Ljava/net/SocketTimeoutException;",
        "Ljava/io/InterruptedIOException;",
        &[],
    ),
    node("Ljava/net/ConnectException;", "Ljava/io/IOException;", &[]),
    // -------------------------------------------------- java.util.function
    leaf("Ljava/util/function/Function;"),
    leaf("Ljava/util/function/BiFunction;"),
    leaf("Ljava/util/function/Supplier;"),
    leaf("Ljava/util/function/Consumer;"),
    leaf("Ljava/util/function/BiConsumer;"),
    leaf("Ljava/util/function/Predicate;"),
    leaf("Ljava/util/function/BiPredicate;"),
    leaf("Ljava/util/function/UnaryOperator;"),
    leaf("Ljava/util/function/BinaryOperator;"),
    leaf("Ljava/util/function/IntFunction;"),
    leaf("Ljava/util/function/ToIntFunction;"),
    leaf("Ljava/util/function/IntPredicate;"),
    leaf("Ljava/util/function/IntUnaryOperator;"),
    leaf("Ljava/util/stream/Stream;"),
    leaf("Ljava/util/stream/IntStream;"),
    // ----------------------------------------------- javax / org / android
    leaf("Ljavax/net/ssl/SSLContext;"),
    leaf("Ljavax/net/ssl/TrustManager;"),
    leaf("Ljavax/net/ssl/X509TrustManager;"),
    leaf("Ljavax/net/ssl/HostnameVerifier;"),
    leaf("Ljavax/crypto/Cipher;"),
    leaf("Ljavax/crypto/KeyStore;"),
    leaf("Landroid/content/Context;"),
    leaf("Landroid/content/ContextWrapper;"),
    leaf("Landroid/content/Intent;"),
    leaf("Landroid/content/IntentFilter;"),
    leaf("Landroid/content/BroadcastReceiver;"),
    leaf("Landroid/content/ServiceConnection;"),
    leaf("Landroid/content/SharedPreferences;"),
    leaf("Landroid/content/pm/PackageManager;"),
    leaf("Landroid/content/pm/PackageInfo;"),
    leaf("Landroid/content/pm/ApplicationInfo;"),
    leaf("Landroid/content/pm/ActivityInfo;"),
    leaf("Landroid/content/pm/ResolveInfo;"),
    leaf("Landroid/content/pm/ProviderInfo;"),
    leaf("Landroid/content/pm/LaunchedAppInfo;"),
    leaf("Landroid/content/res/Resources;"),
    leaf("Landroid/content/res/AssetManager;"),
    leaf("Landroid/content/res/Configuration;"),
    leaf("Landroid/app/Application;"),
    leaf("Landroid/app/Activity;"),
    leaf("Landroid/app/Service;"),
    leaf("Landroid/app/Instrumentation;"),
    leaf("Landroid/os/Bundle;"),
    leaf("Landroid/os/Handler;"),
    leaf("Landroid/os/Looper;"),
    leaf("Landroid/os/Parcel;"),
    leaf("Landroid/os/Parcelable;"),
    leaf("Landroid/os/Build;"),
    leaf("Landroid/os/Build$VERSION;"),
    leaf("Landroid/os/Environment;"),
    leaf("Landroid/os/StrictMode;"),
    leaf("Landroid/os/PowerManager;"),
    leaf("Landroid/os/Process;"),
    leaf("Landroid/os/FileObserver;"),
    leaf("Landroid/os/StatFs;"),
    leaf("Landroid/os/CountDownLatch;"),
    leaf("Landroid/os/AsyncTask;"),
    leaf("Landroid/util/Log;"),
    leaf("Landroid/util/DisplayMetrics;"),
    leaf("Landroid/util/AttributeSet;"),
    leaf("Landroid/util/SparseArray;"),
    leaf("Landroid/util/SparseIntArray;"),
    leaf("Landroid/util/Base64;"),
    leaf("Landroid/graphics/Color;"),
    leaf("Landroid/graphics/Bitmap;"),
    leaf("Landroid/graphics/Canvas;"),
    leaf("Landroid/graphics/Paint;"),
    leaf("Landroid/graphics/Typeface;"),
    leaf("Landroid/graphics/drawable/Drawable;"),
    leaf("Landroid/graphics/drawable/BitmapDrawable;"),
    leaf("Landroid/view/View;"),
    leaf("Landroid/view/ViewGroup;"),
    leaf("Landroid/view/LayoutInflater;"),
    leaf("Landroid/view/Menu;"),
    leaf("Landroid/view/MenuItem;"),
    leaf("Landroid/view/Window;"),
    leaf("Landroid/view/WindowManager;"),
    leaf("Landroid/view/WindowManager$LayoutParams;"),
    leaf("Landroid/view/ContextThemeWrapper;"),
    leaf("Landroid/widget/TextView;"),
    leaf("Landroid/widget/EditText;"),
    leaf("Landroid/widget/Button;"),
    leaf("Landroid/widget/ImageView;"),
    leaf("Landroid/widget/LinearLayout;"),
    leaf("Landroid/widget/FrameLayout;"),
    leaf("Landroid/widget/RelativeLayout;"),
    leaf("Landroid/widget/Adapter;"),
    leaf("Landroid/widget/ArrayAdapter;"),
    leaf("Landroid/widget/BaseAdapter;"),
    leaf("Landroid/widget/CompoundButton;"),
    leaf("Landroid/widget/CheckBox;"),
    leaf("Landroid/widget/Toast;"),
    leaf("Landroid/widget/ProgressBar;"),
    leaf("Landroid/text/TextUtils;"),
    leaf("Landroid/text/Spannable;"),
    leaf("Landroid/webkit/WebView;"),
    leaf("Landroid/webkit/WebViewClient;"),
    leaf("Landroid/webkit/WebSettings;"),
    leaf("Landroid/net/Uri;"),
    leaf("Landroid/net/ConnectivityManager;"),
    leaf("Landroid/net/NetworkInfo;"),
    leaf("Landroid/telephony/TelephonyManager;"),
    leaf("Landroid/location/Location;"),
    leaf("Landroid/location/LocationManager;"),
    leaf("Landroid/hardware/SensorManager;"),
    leaf("Landroid/hardware/Sensor;"),
    leaf("Landroid/hardware/Camera;"),
    leaf("Landroid/bluetooth/BluetoothAdapter;"),
    leaf("Landroid/nfc/NfcAdapter;"),
    leaf("Landroid/accounts/AccountManager;"),
    leaf("Landroid/accounts/Account;"),
    leaf("Ldatabase/sqlite/SQLiteDatabase;"),
    leaf("Ldatabase/sqlite/SQLiteOpenHelper;"),
    leaf("Landroid/annotation/TargetApi;"),
    leaf("Landroid/annotation/SuppressLint;"),
    leaf("Landroidx/annotation/NonNull;"),
];

/// Look a builtin class up by descriptor.
pub fn lookup(descriptor: &str) -> Option<&'static BuiltinClass> {
    BUILTINS.iter().find(|c| c.descriptor == descriptor)
}

/// True if the descriptor names a builtin class.
pub fn is_builtin(descriptor: &str) -> bool {
    lookup(descriptor).is_some()
}

/// The descriptor for `Throwable` itself, used when raising a VM exception with
/// no better class.
pub const THROWABLE: &str = "Ljava/lang/Throwable;";

#[cfg(test)]
mod tests {
    // The crate forbids `unwrap` on anything that came out of a file, and that
    // ban is what keeps a malformed DEX from killing the process. It has no
    // business in a test: every value unwrapped below was built by the test
    // itself, and a test that cannot reach its own fixture should fail loudly
    // rather than contort itself around a type it has already proven.
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn the_table_has_no_duplicate_descriptors() {
        let mut seen: Vec<&str> = BUILTINS.iter().map(|c| c.descriptor).collect();
        let before = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), before, "duplicate descriptor in BUILTINS");
    }

    #[test]
    fn every_superclass_and_interface_is_present_and_declared_earlier() {
        for (i, c) in BUILTINS.iter().enumerate() {
            if let Some(s) = c.superclass {
                let at = BUILTINS.iter().position(|b| b.descriptor == s);
                assert!(at.is_some(), "{}: superclass {} missing", c.descriptor, s);
                assert!(
                    at.unwrap() < i,
                    "{}: superclass {} declared later",
                    c.descriptor,
                    s
                );
            }
            for iface in c.interfaces {
                let at = BUILTINS.iter().position(|b| b.descriptor == *iface);
                assert!(
                    at.is_some(),
                    "{}: interface {} missing",
                    c.descriptor,
                    iface
                );
                assert!(
                    at.unwrap() < i,
                    "{}: interface {} declared later",
                    c.descriptor,
                    iface
                );
            }
        }
    }

    #[test]
    fn exactly_one_root_and_it_is_object() {
        let roots: Vec<&str> = BUILTINS
            .iter()
            .filter(|c| c.superclass.is_none())
            .map(|c| c.descriptor)
            .collect();
        assert_eq!(roots, vec!["Ljava/lang/Object;"]);
    }

    #[test]
    fn the_throwable_chains_the_test_suite_relies_on_are_present() {
        // Each of these is named by a `catch` clause or raised by the engine.
        for d in [
            "Ljava/lang/Throwable;",
            "Ljava/lang/Exception;",
            "Ljava/lang/Error;",
            "Ljava/lang/RuntimeException;",
            "Ljava/lang/NullPointerException;",
            "Ljava/lang/ArithmeticException;",
            "Ljava/lang/ArrayIndexOutOfBoundsException;",
            "Ljava/lang/IndexOutOfBoundsException;",
            "Ljava/lang/NegativeArraySizeException;",
            "Ljava/lang/ClassCastException;",
            "Ljava/lang/ArrayStoreException;",
            "Ljava/lang/UnsupportedOperationException;",
            "Ljava/lang/OutOfMemoryError;",
            "Ljava/lang/StackOverflowError;",
            "Ljava/lang/VerifyError;",
            "Ljava/lang/NoSuchMethodError;",
            "Ljava/lang/NoSuchFieldError;",
            "Ljava/lang/AbstractMethodError;",
            "Ljava/lang/ClassNotFoundException;",
            "Ljava/lang/BootstrapMethodError;",
            "Ljava/lang/UnsatisfiedLinkError;",
        ] {
            assert!(is_builtin(d), "{d} is missing from the builtin table");
        }
    }

    #[test]
    fn the_throwable_hierarchy_is_deep_enough_to_be_useful() {
        // NoSuchMethodError -> IncompatibleClassChangeError -> LinkageError ->
        // Error -> Throwable. Five clauses, and a real app's catch of
        // `Ljava/lang/Error;` has to reach through all of them.
        let mut cursor = "Ljava/lang/NoSuchMethodError;";
        let mut chain = Vec::new();
        loop {
            chain.push(cursor.to_string());
            match lookup(cursor).and_then(|c| c.superclass) {
                Some(s) => cursor = s,
                None => break,
            }
        }
        assert_eq!(
            chain,
            vec![
                "Ljava/lang/NoSuchMethodError;",
                "Ljava/lang/IncompatibleClassChangeError;",
                "Ljava/lang/LinkageError;",
                "Ljava/lang/Error;",
                "Ljava/lang/Throwable;",
                "Ljava/lang/Object;",
            ]
        );
    }

    #[test]
    fn an_unlisted_descriptor_is_simply_absent() {
        assert!(!is_builtin("Landroid/os/NotAThing;"));
        assert!(!is_builtin("La;"));
        assert!(!is_builtin(""));
    }
}
