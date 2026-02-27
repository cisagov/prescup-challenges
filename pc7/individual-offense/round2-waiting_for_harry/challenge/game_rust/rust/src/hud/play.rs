use godot::prelude::*;
use godot::classes::{AudioStreamPlayer2D, CanvasLayer, ICanvasLayer, Label};

#[derive(GodotClass)]
#[class(init, base=CanvasLayer)]
pub struct HudPlay {
    base: Base<CanvasLayer>,
}

impl super::HudState for HudPlay {
    fn begin(&mut self) {
        self.base().get_node_as::<AudioStreamPlayer2D>("Music").play();
    }

    fn end(&mut self) {
        self.base().get_node_as::<AudioStreamPlayer2D>("Music").stop();
    }
}

#[godot_api]
impl HudPlay {
    #[func]
    pub fn update_score(&self, score: i32) {
        self.base().get_node_as::<Label>("Score").set_text(&format!("{}", score));
    }
}


#[godot_api]
impl ICanvasLayer for HudPlay {
    fn ready(&mut self) {
        godot_dbg!("HUDPlay ready: is_visible = {}", self.base().is_visible());
    }
}