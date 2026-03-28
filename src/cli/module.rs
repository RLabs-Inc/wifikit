//! Module trait — unified interface for scanner and attack modules.
//!
//! Every module (scanner, each attack) implements this trait. The shell
//! manages modules through this interface without knowing their internals.
//!
//! Architecture:
//!   - Modules receive a SharedAdapter via start() and spawn their own thread.
//!   - The scanner keeps running while attacks run alongside it.
//!   - Channel contention is handled by SharedAdapter's lock mechanism:
//!     attacks call lock_channel(), scanner pauses hopping until unlock.
//!   - Modules expose real-time state via render() and status_segments()
//!     which read from internal Arc<Mutex<State>> (snapshot pattern).
//!   - The shell manages a focus stack of running modules. Ctrl+N/P cycles focus.
//!   - When a module finishes, its results freeze to scrollback via freeze_summary().

use std::any::Any;

// ═══════════════════════════════════════════════════════════════════════════════
//  Module trait
// ═══════════════════════════════════════════════════════════════════════════════

/// Unified module interface for the shell.
///
/// Lifecycle:
///   1. `new(params)` → module created with configuration
///   2. `start(shared)` → spawns background thread with SharedAdapter
///   3. Shell polls `is_running()` / `is_done()` + calls `render()` at 20fps
///   4. User or timeout calls `signal_stop()` → non-blocking
///   5. Background thread returns → `is_done()` becomes true
///   6. Shell calls `freeze_summary()` → prints results to scrollback
///   7. Module popped from focus stack
///
/// Threading:
///   - Background thread runs the attack/scan logic (owns SharedAdapter clone)
///   - `render()`, `handle_key()`, `status_segments()` run on the UI thread
///   - Communication between them uses Arc<Mutex<Info>> + Arc<EventRing<Event>>
///   - The Module implementation owns both sides of these Arcs
pub trait Module: Send {
    // ── Identity ──

    /// Human-readable module name for display (e.g., "scanner", "pmkid", "wps").
    fn name(&self) -> &str;

    /// One-line description (e.g., "PMKID extraction attack").
    fn description(&self) -> &str;

    /// Module type for lifecycle decisions.
    fn module_type(&self) -> ModuleType;

    // ── Adapter lifecycle ──

    /// Start the module using SharedAdapter. Spawns its own background thread.
    ///
    /// The module shares the adapter with other modules via SharedAdapter.
    /// The scanner keeps running while attacks run alongside it.
    /// Channel contention is handled by SharedAdapter's lock mechanism:
    /// attacks call lock_channel(), scanner pauses hopping until unlock.
    fn start(&mut self, shared: crate::adapter::SharedAdapter);

    /// Signal the module to stop. Non-blocking — sets an AtomicBool.
    /// The background thread checks this flag and returns when it sees false.
    fn signal_stop(&self);

    /// Check if the module's work is actively running.
    /// Non-blocking — reads an AtomicBool.
    fn is_running(&self) -> bool;

    /// Check if the background thread has returned (module finished).
    /// Non-blocking. For continuous modules (scanner), this is only true
    /// after signal_stop() + the thread returns.
    fn is_done(&self) -> bool;

    // ── UI: Rendering ──

    /// View definitions — what tabs/views does this module expose?
    /// The shell uses this to render the tab bar and dispatch handle_key.
    fn views(&self) -> &[ViewDef];

    /// Render the active view. Returns lines of styled text for the active zone.
    ///
    /// Implementation MUST use the snapshot pattern:
    ///   1. Lock state mutex
    ///   2. Clone the subset needed for this view
    ///   3. Unlock
    ///   4. Render from the snapshot (no lock held)
    ///
    /// Takes `&mut self` because modules may cache snapshots between renders
    /// to avoid redundant cloning (refresh once per cycle, render from cache).
    ///
    /// `view` is the index into `views()`. `width` and `height` are the
    /// available terminal dimensions for this module's content area.
    fn render(&mut self, view: usize, width: u16, height: u16) -> Vec<String>;

    /// Handle a keypress in Normal Mode. Returns true if the key was consumed.
    /// The shell calls this for the focused module. If the module doesn't
    /// handle the key, the shell processes it (mode switch, focus cycling, etc.).
    fn handle_key(&mut self, key: &prism::KeyEvent, view: usize) -> bool;

    /// Status bar segments for this module. Shown even when not focused.
    /// Every running module contributes segments to the status bar.
    fn status_segments(&self) -> Vec<StatusSegment>;

    // ── Results ──

    /// Freeze results to scrollback when the module completes.
    /// Returns styled lines that are printed to the output zone as
    /// a permanent record (audit trail).
    ///
    /// Called once after is_done() returns true, before the module
    /// is popped from the focus stack.
    fn freeze_summary(&self, width: u16) -> Vec<String>;

    // ── Downcasting ──

    /// Downcast support — allows the shell to access concrete module types
    /// for module-specific operations (e.g., ScannerModule::get_aps).
    fn as_any(&self) -> &dyn Any;

    /// Mutable downcast support.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Supporting types
// ═══════════════════════════════════════════════════════════════════════════════

/// Module type — determines lifecycle behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleType {
    /// Continuous module (scanner). Runs until explicitly stopped.
    /// Not auto-removed from focus stack when work finishes.
    /// Can be restarted after stop.
    Scanner,

    /// Time-limited module (attacks). Runs until complete or stopped.
    /// Auto-freezes results and pops from focus stack when done.
    Attack,
}

/// View definition for a module's tab bar.
#[derive(Debug, Clone)]
pub struct ViewDef {
    /// Tab label shown in the tab bar (e.g., "APs", "Clients", "Events").
    pub label: String,
    /// Short key hint (e.g., "1" for tab switching).
    pub key_hint: Option<String>,
}

impl ViewDef {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            key_hint: None,
        }
    }

    pub fn with_key(mut self, key: impl Into<String>) -> Self {
        self.key_hint = Some(key.into());
        self
    }
}

/// A styled segment for the status bar.
#[derive(Debug, Clone)]
pub struct StatusSegment {
    pub text: String,
    pub style: SegmentStyle,
}

/// Status bar segment styling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentStyle {
    /// Normal text.
    Normal,
    /// Dimmed/secondary text.
    Dim,
    /// Bold/emphasized text.
    Bold,
    /// Green (success, connected, captured).
    Green,
    /// Green bold (strong success emphasis).
    GreenBold,
    /// Yellow (warning, partial, in-progress).
    Yellow,
    /// Yellow bold (strong warning emphasis).
    YellowBold,
    /// Red (error, attack active, vulnerability).
    Red,
    /// Red bold (attack header, critical state).
    RedBold,
    /// Cyan (informational, progress).
    Cyan,
    /// Cyan bold (scanner label, active module).
    CyanBold,
    /// Magenta (WPS attack).
    Magenta,
    /// Magenta bold (WPS attack header).
    MagentaBold,
}

impl StatusSegment {
    pub fn new(text: impl Into<String>, style: SegmentStyle) -> Self {
        Self {
            text: text.into(),
            style,
        }
    }

    /// Render this segment with ANSI styling.
    pub fn render(&self) -> String {
        let s = prism::s();
        match self.style {
            SegmentStyle::Normal => self.text.clone(),
            SegmentStyle::Dim => s.dim().paint(&self.text),
            SegmentStyle::Bold => s.bold().paint(&self.text),
            SegmentStyle::Green => s.green().paint(&self.text),
            SegmentStyle::GreenBold => s.green().bold().paint(&self.text),
            SegmentStyle::Yellow => s.yellow().paint(&self.text),
            SegmentStyle::YellowBold => s.yellow().bold().paint(&self.text),
            SegmentStyle::Red => s.red().paint(&self.text),
            SegmentStyle::RedBold => s.red().bold().paint(&self.text),
            SegmentStyle::Cyan => s.cyan().paint(&self.text),
            SegmentStyle::CyanBold => s.cyan().bold().paint(&self.text),
            SegmentStyle::Magenta => s.magenta().paint(&self.text),
            SegmentStyle::MagentaBold => s.magenta().bold().paint(&self.text),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Focus Stack — manages active modules
// ═══════════════════════════════════════════════════════════════════════════════

/// Focus stack managing running modules.
///
/// The active module (top of stack) gets keyboard focus and renders
/// in the active zone. All running modules contribute status segments.
/// Ctrl+N/P cycles which module has focus.
pub struct FocusStack {
    modules: Vec<Box<dyn Module>>,
    focus_index: usize,
}

impl FocusStack {
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
            focus_index: 0,
        }
    }

    /// Push a new module onto the stack and give it focus.
    pub fn push(&mut self, module: Box<dyn Module>) {
        self.modules.push(module);
        self.focus_index = self.modules.len() - 1;
    }

    /// Get the focused module (mutable).
    pub fn focused_mut(&mut self) -> Option<&mut Box<dyn Module>> {
        self.modules.get_mut(self.focus_index)
    }

    /// Get the focused module (immutable).
    pub fn focused(&self) -> Option<&Box<dyn Module>> {
        self.modules.get(self.focus_index)
    }

    /// Cycle focus to the next running module.
    pub fn focus_next(&mut self) {
        if self.modules.len() <= 1 {
            return;
        }
        self.focus_index = (self.focus_index + 1) % self.modules.len();
    }

    /// Cycle focus to the previous running module.
    pub fn focus_prev(&mut self) {
        if self.modules.len() <= 1 {
            return;
        }
        if self.focus_index == 0 {
            self.focus_index = self.modules.len() - 1;
        } else {
            self.focus_index -= 1;
        }
    }

    /// Remove and return completed attack modules.
    /// Scanner modules are never auto-removed.
    /// Returns the removed modules for freeze_summary().
    pub fn drain_completed(&mut self) -> Vec<Box<dyn Module>> {
        let mut completed = Vec::new();
        let mut i = 0;
        while i < self.modules.len() {
            if self.modules[i].module_type() == ModuleType::Attack && self.modules[i].is_done() {
                completed.push(self.modules.remove(i));
                // Adjust focus index
                if self.focus_index >= self.modules.len() && !self.modules.is_empty() {
                    self.focus_index = self.modules.len() - 1;
                }
            } else {
                i += 1;
            }
        }
        completed
    }

    /// Get all modules for status bar rendering.
    pub fn all(&self) -> &[Box<dyn Module>] {
        &self.modules
    }

    /// Number of modules in the stack.
    pub fn len(&self) -> usize {
        self.modules.len()
    }

    /// Check if the stack is empty.
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    /// Find a module by name.
    pub fn find_by_name(&self, name: &str) -> Option<usize> {
        self.modules.iter().position(|m| m.name() == name)
    }

    /// Remove a module by index.
    pub fn remove(&mut self, index: usize) -> Box<dyn Module> {
        let module = self.modules.remove(index);
        if self.focus_index >= self.modules.len() && !self.modules.is_empty() {
            self.focus_index = self.modules.len() - 1;
        }
        module
    }

    /// Current focus index.
    pub fn focus_index(&self) -> usize {
        self.focus_index
    }

    /// Get mutable reference to a module by index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Box<dyn Module>> {
        self.modules.get_mut(index)
    }

    /// Get mutable reference to all modules.
    pub fn all_mut(&mut self) -> &mut [Box<dyn Module>] {
        &mut self.modules
    }

    /// Downcast the focused module to a concrete type.
    pub fn focused_as<T: 'static>(&self) -> Option<&T> {
        self.focused().and_then(|m| m.as_any().downcast_ref::<T>())
    }

    /// Downcast the focused module to a concrete type (mutable).
    pub fn focused_as_mut<T: 'static>(&mut self) -> Option<&mut T> {
        self.focused_mut().and_then(|m| m.as_any_mut().downcast_mut::<T>())
    }

    /// Find and downcast a module by name.
    pub fn find_as<T: 'static>(&self, name: &str) -> Option<&T> {
        self.modules.iter()
            .find(|m| m.name() == name)
            .and_then(|m| m.as_any().downcast_ref::<T>())
    }

    /// Find and downcast a module by name (mutable).
    pub fn find_as_mut<T: 'static>(&mut self, name: &str) -> Option<&mut T> {
        self.modules.iter_mut()
            .find(|m| m.name() == name)
            .and_then(|m| m.as_any_mut().downcast_mut::<T>())
    }

    /// Check if any attack module is running.
    pub fn has_active_attack(&self) -> bool {
        self.modules.iter().any(|m| m.module_type() == ModuleType::Attack && !m.is_done())
    }

    /// Signal stop on the first active attack module.
    pub fn stop_active_attack(&self) -> Option<&str> {
        for module in &self.modules {
            if module.module_type() == ModuleType::Attack && !module.is_done() {
                let name = module.name();
                module.signal_stop();
                return Some(name);
            }
        }
        None
    }
}
