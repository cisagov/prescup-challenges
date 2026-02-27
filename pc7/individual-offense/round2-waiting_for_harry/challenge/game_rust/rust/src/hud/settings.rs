use godot::prelude::*;
use godot::classes::{CanvasLayer, ICanvasLayer};

#[derive(GodotClass)]
#[class(init, base=CanvasLayer)]
pub struct HudSettings {
    base: Base<CanvasLayer>,
}

#[godot_api]
impl HudSettings {
    #[func]
    fn on_settings_return(&mut self) {
        self.signals().settings_finished().emit();
    }

    #[signal]
    fn settings_finished();
}

impl super::HudState for HudSettings {
    fn begin(&mut self) {}
    fn end(&mut self) {}
}

#[godot_api]
impl ICanvasLayer for HudSettings {
    fn ready(&mut self) {
        godot_dbg!("HUDSettings ready: is_visible = {}", self.base().is_visible());
    }
}