use godot::prelude::*;
use godot::classes::{AnimatedSprite2D, RigidBody2D, IRigidBody2D};

#[derive(GodotClass)]
#[class(init, base=RigidBody2D)]
pub struct Mob {
    base: Base<RigidBody2D>,
}

#[godot_api]
impl Mob {
    #[func]
    fn on_visible_on_screen_notifier_2d_screen_exited(&mut self) {
        self.base_mut().queue_free();
    }
}

#[godot_api]
impl IRigidBody2D for Mob {
    fn ready(&mut self) {
        let mut animated_sprite = self.base().get_node_as::<AnimatedSprite2D>("AnimatedSprite2D");
        let mob_types: Array<Variant> = animated_sprite
            .get_sprite_frames()
            .expect("Mob should have sprite frames")
            .get_animation_names()
            .to_var_array();
        animated_sprite.set_animation(mob_types.pick_random().expect("Mob should have type").stringify().arg());
        animated_sprite.play();
        godot_dbg!("Mob ready");
    }
}