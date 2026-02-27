extends RefCounted
class_name ac_validator

# override
func with(value) -> ac_validator:
	# Save the original data
	return self
	
# override
func check(value) -> bool:
	# Check that the data has not been altered by cheating tools.
	return false
	
# override
func source():
	# Return the original data
	return 0
	
