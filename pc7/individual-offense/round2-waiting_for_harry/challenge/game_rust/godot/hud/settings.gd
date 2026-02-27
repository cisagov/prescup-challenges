extends HudSettings
var volume = 100
var swipes = 0


# Called when the node enters the scene tree for the first time.
func _ready() -> void:
	pass # Replace with function body.


# Called every frame. 'delta' is the elapsed time since the previous frame.
func _process(_delta: float) -> void:
	pass


func _on_drag_ended(value_changed: bool) -> void:
	# TODO: Switching to debug mode should be deleted before we make the game public
	# Especially because they want everything to be in rust not in the easier language :(
	if value_changed:
		var slider_value = $VolumeSlider.value
		
		volume = slider_value
		swipes += 1;
		print("Another swipe")
		if swipes > 8:
			JavaScriptBridge.eval("window.location.href = 'https://dodgethecreeps/debug/index.html';", true);
