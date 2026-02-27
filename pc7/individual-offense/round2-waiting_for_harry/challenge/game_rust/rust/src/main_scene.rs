use godot::classes::{Marker2D, PathFollow2D, RigidBody2D, Script, Timer};
use godot::prelude::*;
use godot::{classes::{Node, INode, PackedScene}, obj::Gd};
use crate::hud::Hud;
use crate::player::Player;

#[derive(GodotClass)]
#[class(init, base=Node)]
struct Main {
    #[export]
    mob_scene: OnEditor<Gd<PackedScene>>,
    #[init(val = OnReady::manual())]
    score: OnReady<Gd<Object>>,
    #[init(val = OnReady::manual())]
    ac_pool: OnReady<Gd<Object>>,
    base: Base<Node>,
}

#[godot_api]
impl Main {

    #[func]
    fn game_over(&mut self) {
        self.base_mut().get_node_as::<Timer>("ScoreTimer").stop();
        self.base_mut().get_node_as::<Timer>("MobTimer").stop();
        self.base_mut().get_node_as::<Hud>("HUD").bind_mut().end();
    }

    #[func]
    fn new_game(&mut self) {
        self.base_mut().get_tree().expect("Should have tree").call_group("mobs", "queue_free", &[]);
        self.score.call("set_value", &[0.to_variant()]);
        self.ac_pool.call("set_value", &["score".to_variant(), self.score.to_variant()]);
        self.base_mut().get_node_as::<Hud>("HUD").bind_mut().prepare();
    }

    #[func]
    fn start_new_game(&mut self) {
        let initial_score = self.ac_pool.call("get_value", &["score".to_variant()]).call("value", &[]).to::<i32>();
        self.base_mut().get_node_as::<Hud>("HUD").bind_mut().update_score(initial_score);
        let start_position = self.base().get_node_as::<Marker2D>("StartPosition").get_position();
        self.base_mut().get_node_as::<Player>("Player").bind_mut().start(start_position);
        self.base_mut().get_node_as::<Timer>("ScoreTimer").start_ex().time_sec(1.0).done();
        self.base_mut().get_node_as::<Timer>("MobTimer").start_ex().time_sec(1.0).done();
    }

    #[func]
    fn on_mob_timer_timeout(&mut self) {
        let mut mob = self.mob_scene.try_instantiate_as::<RigidBody2D>().expect("Should be able to instance mob scene");
        let mut mob_spawn_location = self.base_mut().get_node_as::<PathFollow2D>("MobPath/MobSpawnLocation");
        mob_spawn_location.set_progress_ratio(rand::random::<f32>());

        mob.set_position(mob_spawn_location.get_position());

        let direction = mob_spawn_location.get_rotation() + 
            std::f32::consts::FRAC_PI_2 + 
            rand::random_range(-std::f32::consts::FRAC_PI_4..std::f32::consts::FRAC_PI_4);
        mob.set_rotation(direction);

        let speed = rand::random_range(150.0..250.0);
        let velocity = Vector2::new(speed, 0.0).rotated(direction);
        mob.set_linear_velocity(velocity);

        self.base_mut().add_child(&mob);
    }

    #[func]
    fn on_score_timer_timeout(&mut self) {
        let current_score = self.ac_pool.call("get_value", &["score".to_variant()]).call("value", &[]).to::<i32>();
        let new_score = current_score + 1;
        self.score.call("set_value", &[new_score.to_variant()]);
        self.ac_pool.call("set_value", &["score".to_variant(), self.score.to_variant()]);
        self.base_mut().get_node_as::<Hud>("HUD").bind_mut().update_score(new_score);
    }
}

#[godot_api]
impl INode for Main {
    fn ready(&mut self) {
        let mut ac_int: Gd<Script> = load("res://addons/anti-cheating/int_value.gd");
        godot_dbg!("Loaded ac_int: {:?}", ac_int);
        let mut  ac_node: Gd<Script> = load("res://addons/anti-cheating/ac_node.gd");
        godot_dbg!("Loaded ac_node: {:?}", ac_node);
        let ac_global_pool = ac_node.call("new", &[]).to::<Gd<Object>>();
        self.ac_pool.init(ac_global_pool);
        self.ac_pool.set("disturb", &5.to_variant());
        self.score.init(ac_int.call("new", &[]).to::<Gd<Object>>());
        self.ac_pool.call("set_value", &["score".to_variant(), self.score.to_variant()]);
        godot_dbg!("Main ready");
    }
}