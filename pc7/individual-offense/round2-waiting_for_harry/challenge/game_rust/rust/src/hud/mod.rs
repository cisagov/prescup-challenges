/// The state machine flow should be:
/// Start -> Preparing -> Play -> End -> Start
pub mod start;
pub mod preparing;
pub mod play;
pub mod end;
pub mod settings;

use godot::obj::WithBaseField;
use godot::prelude::*;
use godot::classes::{CanvasLayer, ICanvasLayer};

trait HudState {
    fn begin(&mut self);
    fn end(&mut self);
}

#[derive(Debug)]
pub(crate) enum HudStates {
    Start,
    Preparing,
    Play,
    End,
    Settings,
}

#[derive(GodotClass)]
#[class(init, base=CanvasLayer)]
pub(crate) struct Hud {
    #[init(node = "Start")]
    start: OnReady<Gd<start::HudStart>>,
    #[init(node = "Preparing")]
    preparing: OnReady<Gd<preparing::HudPreparing>>,
    #[init(node = "Play")]
    play: OnReady<Gd<play::HudPlay>>,
    #[init(node = "End")]
    end: OnReady<Gd<end::HudEnd>>,
    #[init(node = "Settings")]
    settings: OnReady<Gd<settings::HudSettings>>,
    #[init(val = HudStates::Start)]
    current_state: HudStates,
    base: Base<CanvasLayer>,
}

fn switch_states(from: &mut Gd<impl HudState + WithBaseField<Base = CanvasLayer>>, to: &mut Gd<impl HudState + WithBaseField<Base = CanvasLayer>>) {
    let mut from = from.bind_mut();
    from.end();
    from.base_mut().hide();

    let mut to = to.bind_mut();
    to.begin();
    to.base_mut().show();
}

#[godot_api]
impl Hud {
    #[signal]
    fn start_game();
    #[signal]
    fn play_game();

    pub fn setup(&mut self) {
        godot_dbg!("HUD ({:?}) setup called", self.current_state);
        if let HudStates::Start = &self.current_state {
            return;
        } else if let HudStates::End = self.current_state {
            switch_states(&mut self.end, &mut self.start);
        } else {
            unreachable!()
        }
        self.current_state = HudStates::Start;
    }

    pub fn prepare(&mut self) {
        godot_dbg!("HUD ({:?}) prepare called", self.current_state);
        if let HudStates::Start = self.current_state {
            switch_states(&mut self.start, &mut self.preparing);
        } else {
            unreachable!()
        }
        self.current_state = HudStates::Preparing;
    }

    pub fn settings(&mut self) {
        godot_dbg!("HUD ({:?}) settings called", self.current_state);
        if let HudStates::Start = self.current_state {
            switch_states(&mut self.start, &mut self.settings);
        } else {
            unreachable!()
        }
        self.current_state = HudStates::Settings;
    }

    pub fn settings_return(&mut self) {
        godot_dbg!("HUD ({:?}) settings called", self.current_state);
        if let HudStates::Settings = self.current_state {
            switch_states(&mut self.settings, &mut self.start);
        } else {
            unreachable!()
        }
        self.current_state = HudStates::Start;
    }

    pub fn play(&mut self) {
        godot_dbg!("HUD ({:?}) play called", self.current_state);
        if let HudStates::Preparing = self.current_state {
            switch_states(&mut self.preparing, &mut self.play);
        } else {
            unreachable!()
        }
        self.current_state = HudStates::Play;
    }

    pub fn end(&mut self) {
        godot_dbg!("HUD ({:?}) end called", self.current_state);
        if let HudStates::Play = self.current_state {
            switch_states(&mut self.play, &mut self.end);
            self.current_state = HudStates::End;
        } else {
            unreachable!();
        }
    }

    pub fn update_score(&mut self, score: i32) {
        godot_dbg!("HUD ({:?}) update_score called with score={}", self.current_state, score);
        if let HudStates::Play = self.current_state {
            self.play.bind().update_score(score);
            self.end.bind_mut().update_score(score);
        }
    }

    #[func]
    fn on_start_game(&mut self) {
        self.signals().start_game().emit();
    }

    #[func]
    fn on_settings(&mut self) {
        self.settings();
    }

    #[func]
    fn on_game_over_finish(&mut self) {
        self.setup();
    }

    #[func]
    fn on_preparing_finish(&mut self) {
        self.play();
        self.signals().play_game().emit();
    }

    #[func]
    fn on_settings_return(&mut self) {
        self.settings_return();
    }
}

#[godot_api]
impl ICanvasLayer for Hud {
    fn ready(&mut self) {
        godot_dbg!("HUD ready: is_visible = {}", self.base().is_visible());
    }
}