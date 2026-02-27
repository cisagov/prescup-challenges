use godot::prelude::*;
use godot::classes::{AnimatedSprite2D, Area2D, CollisionShape2D, IArea2D, Input};

#[derive(GodotClass)]
#[class(init, base=Area2D)]
pub struct Player {
    #[export]
    #[init(val = 400)]
    speed: i32,
    #[init(val = OnReady::manual())]
    screen_size: OnReady<Vector2>,
    base: Base<Area2D>,
}

#[godot_api]
impl Player {
    #[signal]
    fn hit();

    #[func]
    fn on_body_entered(&mut self, _body: Gd<Node2D>) {
        self.base_mut().hide();
        self.signals().hit().emit();
        self.base_mut().get_node_as::<CollisionShape2D>("CollisionShape2D").set_deferred("disabled", &true.to_variant());
    }

    pub fn start(&mut self, position: Vector2) {
        self.base_mut().set_position(position);
        self.base_mut().show();
        self.base_mut().get_node_as::<CollisionShape2D>("CollisionShape2D").set_deferred("disabled", &false.to_variant());
    }
}

#[godot_api]
impl IArea2D for Player {
    fn ready(&mut self) {
        self.screen_size.init(self.base().get_viewport_rect().size);
        self.base_mut().hide();
        godot_dbg!("Player ready");
    }

    fn process(&mut self, delta: f64) {
        let mut velocity = Vector2::ZERO;
        let input = Input::singleton();

        if input.is_action_pressed("move_right") {
            velocity.x += 1.0;
        }
        if input.is_action_pressed("move_left") {
            velocity.x -= 1.0;
        }
        if input.is_action_pressed("move_down") {
            velocity.y += 1.0;
        }
        if input.is_action_pressed("move_up") {
            velocity.y -= 1.0;
        }

        let mut animated_sprite = self.base().get_node_as::<AnimatedSprite2D>("AnimatedSprite2D");
        if velocity.length() > 0.0 {
            velocity = velocity.normalized() * self.speed as f32;
            animated_sprite.play();
        } else {
            animated_sprite.stop();
        }

        let new_position = self.base().get_position() + velocity * delta as f32;
        let new_position = new_position.clamp(Vector2::ZERO, *self.screen_size);
        self.base_mut().set_position(new_position);

        if velocity.x != 0.0 {
            animated_sprite.set_animation("walk");
            animated_sprite.set_flip_v(false);
            animated_sprite.set_flip_h(velocity.x < 0.0);
        } else if velocity.y != 0.0 {
            animated_sprite.set_animation("up");
            animated_sprite.set_flip_v(velocity.y > 0.0);
        }
    }


}