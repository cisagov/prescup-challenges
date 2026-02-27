use godot::prelude::*;
use godot::classes::{CanvasLayer, ICanvasLayer, Label, Timer};

#[derive(GodotClass)]
#[class(init, base=CanvasLayer)]
pub struct HudPreparing {
    index: usize,
    base: Base<CanvasLayer>,
}

impl super::HudState for HudPreparing {
    fn begin(&mut self) {
        self.base().get_node_as::<Timer>("CountdownTimer").start();
        self.base().get_node_as::<Label>("Label").set_text("3!");
        self.index = 0;
    }
    fn end(&mut self) {}
}

#[godot_api]
impl HudPreparing {
    #[signal]
    fn finish();

    #[func]
    fn on_countdown_timeout(&mut self) {
        const TEXTS: [&str; 3] = ["2!", "1!", "Start!"];
        if self.index < 3 {
            self.base().get_node_as::<Label>("Label").set_text(TEXTS[self.index]);
        } else {
            self.base().get_node_as::<Timer>("CountdownTimer").stop();
            self.signals().finish().emit();
        }
        self.index += 1;
    }
}

#[godot_api]
impl ICanvasLayer for HudPreparing {
    fn ready(&mut self) {
        godot_dbg!("HUDPreparing ready: is_visible = {}", self.base().is_visible());
    }
}