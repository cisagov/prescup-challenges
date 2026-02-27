extends RefCounted
class_name ac_value

var _parent: ac_value = null  # Reference to parent
var _parent_key: Variant = null  # Key or index in parent

# Constructor to initialize parent and parent_key
func _init(parent: ac_value = null, parent_key: Variant = null):
	_parent = parent
	_parent_key = parent_key

# Get the validator (returns the default or overridden validator)
func get_validator() -> ac_validator:
	return _get_validator()

# Override for value (returns 0 by default, to be overridden by subclasses)
func value():
	return 0

# Duplicate this value (returns a new instance, to be overridden by subclasses)
func duplicate() -> ac_value:
	return ac_value.new()

# Default validator getter (returns a new instance of ac_validator)
func _get_validator() -> ac_validator:
	return ac_validator.new()

# Notify the parent of the change (to be used when a child modifies its value)
func _notify_parent():
	if _parent:
		_parent.set_value(_parent_key, self)
