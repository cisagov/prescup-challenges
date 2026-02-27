macro_rules! godot_dbg {
    ($($x:tt)*) => {
        {
            #[cfg(debug_assertions)]
            {
                godot::global::godot_print!($($x)*)
            }
            #[cfg(not(debug_assertions))]
            {}
        }
    }
}
mod hud;
mod player;
mod mob;
mod main_scene;

use godot::prelude::*;

struct MyExtension;

#[gdextension]
unsafe impl ExtensionLibrary for MyExtension {
    fn override_wasm_binary() -> Option<&'static str> {
        #[cfg(all(target_arch = "wasm32", feature = "nothreads"))]
        {
            Some("rust.nothreads.wasm")
        }
        #[cfg(all(target_arch = "wasm32", not(feature = "nothreads")))]
        {
            Some("rust.threads.wasm")
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            None
        }
    }
}
