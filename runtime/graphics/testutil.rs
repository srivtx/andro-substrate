//! Test-only drivers for the second backend.
//!
//! # Why this is a module and not a test helper
//!
//! The Canvas2D backend is a real implementation, not a test double, and the
//! tests need to drive a *box tree* through it rather than assemble individual
//! calls. [`canvas2d_program`] is that driver. It lives here, behind
//! `#[doc(hidden)]`, for two reasons:
//!
//! - it is not part of the crate's contract, so it must not appear in the
//!   public API a caller is expected to rely on;
//! - it must not be `#[cfg(test)]`, because the integration tests in
//!   `runtime/graphics/tests/` compile against the *library*, and a
//!   `#[cfg(test)]` item is not visible to them. The `deny(clippy::unwrap_used)`
//!   on the crate does not apply to this module's single `expect`, and there is
//!   no `unwrap`, so nothing here can panic in the shipped paths either.

use shim::layout::BoxNode;

use crate::canvas::{Canvas, Canvas2dCanvas, Viewport};
use crate::draw::DrawConfig;
use crate::error::GraphicsError;
use crate::measure::TextMeasurer;

/// Drive a box tree through the Canvas2D backend and return the generated
/// JavaScript program.
///
/// The banner is drawn inside `begin_frame`, so the returned program already
/// carries the warning text. A caller that wants a bare program can drop the
/// first `fillRect`, and should not.
pub fn canvas2d_program(
    tree: &BoxNode,
    config: &DrawConfig,
    measurer: &dyn TextMeasurer,
) -> String {
    let program = match canvas2d_lines(tree, config, measurer) {
        Ok((lines, report)) => {
            // The statement list is all `to_js` needs, so the header is written
            // here rather than by rebuilding a canvas; the
            // statement list is the same either way, so the program is assembled
            // from the lines with the same header `to_js` writes.
            let mut s = String::new();
            s.push_str("// andro-substrate graphics program.\n");
            s.push_str("// THIS RENDERS THE SHIM'S BOX TREE, NOT THE APP. The app's onDraw\n");
            s.push_str("// code was never executed. See runtime/graphics/capability.rs.\n");
            s.push_str(&format!(
                "// capability: {} reproduced of {} SUB.GFX assumptions\n",
                report.reproduced(),
                crate::GfxId::ALL.len()
            ));
            s.push_str("function substrateDraw(ctx) {\n");
            for l in &lines {
                s.push_str("  ");
                s.push_str(l);
                s.push('\n');
            }
            s.push_str("}\n");
            s
        }
        Err(e) => format!("// graphics: {e}\n"),
    };
    program
}

/// The same walk, returning the raw statement list and the audited report. Used
/// by the tests that count statements.
pub fn canvas2d_lines(
    tree: &BoxNode,
    config: &DrawConfig,
    measurer: &dyn TextMeasurer,
) -> Result<(Vec<String>, crate::capability::CapabilityReport), GraphicsError> {
    config.viewport.checked()?;
    let mut c = Canvas2dCanvas::new("ctx");
    c.begin_frame(config.viewport.rect(), config.viewport.density)?;
    let mut report = crate::draw::DrawReport::default();
    let mut unknown = 0.0f64;
    c.save()?;
    crate::draw::draw_node(
        tree,
        crate::paint::RectF::new(0.0, 0.0, 0.0, 0.0),
        0,
        config,
        measurer,
        &mut c,
        &mut report,
        &mut unknown,
    )?;
    c.restore()?;
    let cap = crate::capability::CapabilityReport::audit(
        crate::error::BackendKind::Canvas2d,
        &crate::canvas::canvas2d_claims(),
        crate::canvas::canvas2d_limitations(),
        |p| c.probe(p),
    );
    Ok((c.lines().to_vec(), cap))
}

/// The default viewport for a test, spelled once.
pub const TEST_VIEWPORT: Viewport = Viewport {
    width_dp: 360.0,
    height_dp: 640.0,
    density: 1.0,
};
