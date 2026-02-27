extends ac_value
class_name ac_int

var _value: int
var _validator: ac_validator
	
func _init(v: int = 0) -> void:
	_value = v
	_validator = get_validator().with(v)
	
func value() -> int:
	if not _validator.check(_value):
		return _validator.source()
	return _value

func set_value(v: int):
	_value = v
	_validator.with(v)
	_notify_parent()
	
# override
func _get_validator() -> ac_validator:
	return preload("int_validator.gd").new()
	
# override
func duplicate() -> ac_value:
	return ac_int.new(_value)

# Override the _add_assign method to handle += operator
func _add_assign(other: int) -> void:
	_value += other
	_validator.with(_value)
	
# Override the _sub_assign method to handle -= operator
func _sub_assign(other: int) -> void:
	_value -= other
	_validator.with(_value)
	
# Override the _mul_assign method to handle *= operator
func _mul_assign(other: int) -> void:
	_value *= other
	_validator.with(_value)
	
# Override the _div_assign method to handle /= operator
func _div_assign(other: int) -> void:
	if other != 0:
		_value /= other
		_validator.with(_value)
	else:
		print("Error: Division by zero")
