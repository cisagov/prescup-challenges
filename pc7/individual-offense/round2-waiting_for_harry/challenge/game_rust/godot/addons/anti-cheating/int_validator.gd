extends ac_validator

var _0: int = 0
var _1: int = 0
var _2: int = 0
var _3: int = 0

func with(value: int) -> ac_validator:
	_2 = Time.get_unix_time_from_system()
	_0 = value - _2
	_1 = value + _2
	_3 = _2 - value
	return self
	
func check(value: int) -> bool:
	return (_0 + _2) == value and (_1 - _2) == value
	
func source() -> int:
	return _2 - _3
	
