use godot::prelude::*;
use godot::classes::{CanvasLayer, ICanvasLayer};

#[derive(GodotClass)]
#[class(init, base=CanvasLayer)]
pub struct HudStart {
    base: Base<CanvasLayer>,
}

#[godot_api]
impl HudStart {
    #[func]
    fn on_start_button_pressed(&mut self) {
        self.signals().start_game().emit();
    }

    #[func]
    fn on_settings_button_pressed(&mut self) {
        self.signals().settings_return().emit();
    }

    #[signal]
    fn start_game();

    #[signal]
    fn settings_return();
}

impl super::HudState for HudStart {
    fn begin(&mut self) {}
    fn end(&mut self) {}
}



#[godot_api]
impl ICanvasLayer for HudStart {
    fn ready(&mut self) {
        godot_dbg!("HUDStart ready: is_visible = {}", self.base().is_visible());
    }
}