extends RefCounted
class_name ac_dict

# ANTI-CHEAT DICTIONARY IMPLEMENTATION
# ====================================
# This class implements an anti-cheat mechanism through data obfuscation and interference.
# The core principle is to make memory scanning and value modification extremely difficult
# by hiding legitimate game values among a sea of fake/duplicate values.

# INTERFERENCE MECHANISM:
# When a value is stored, the system creates multiple fake copies with random keys.
# This makes it nearly impossible for cheaters to identify which memory location
# contains the real value they want to modify (e.g., player health, score, etc.)

# The number of times interference data is generated per stored value.
# Higher values = better anti-cheat protection but worse performance.
# Each real value gets surrounded by 'disturb' number of fake copies.
var disturb: int = 0

# CORE DATA STRUCTURES:
# Private storage for the actual key-value pairs and anti-cheat infrastructure
var _pool: Dictionary = {}              # Main storage: real values + interference data
var _disturb_threads: Dictionary = {}   # Tracks background threads creating interference
var _pool_mutex: Mutex = Mutex.new()   # Thread-safe access to _pool
var _disturb_queue: Array = []          # Queue of values waiting for interference generation

func set_value(key: String, value: ac_value):
	# ANTI-CHEAT VALUE STORAGE:
	# 1. First, clean up any existing interference for this key
	# 2. Store the real value
	# 3. Queue the value for interference generation (fake copies)
	
	_pool_mutex.lock()
	if !_pool.is_empty() and _pool.has(key):
		# Remove old interference patterns before storing new value
		await _quieten(_pool[key])
	_pool[key] = value  # Store the legitimate value
	_pool_mutex.unlock()
	
	# Queue this value for interference generation in background threads
	# This prevents blocking the main thread while creating fake copies
	_disturb_queue.append(value)
	_process_disturbance_queue()

func get_value(key: String, default_value: ac_value = ac_value.new()) -> ac_value:
	# SECURE VALUE RETRIEVAL:
	# Returns the real value associated with the key.
	# Interference values use special prefixed keys, so normal lookups ignore them.
	return _pool[key] if _pool.has(key) else default_value

func has(key: String) -> bool:
	# THREAD-SAFE KEY EXISTENCE CHECK:
	# Only checks for legitimate keys, not interference data
	_pool_mutex.lock()
	var result = _pool.has(key)
	_pool_mutex.unlock()
	return result

func keys() -> Array[String]:
	# RETURNS ALL KEYS (including interference):
	# Note: This includes both real keys and interference keys with "__ac_disturb" prefix
	# In a production system, you might want to filter out interference keys
	var result = _pool.keys()
	return result

func erase(key: String) -> bool:
	# SECURE KEY DELETION:
	# 1. Remove all associated interference data
	# 2. Delete the main key-value pair
	_pool_mutex.lock()
	_silence(_pool[key])  # Clean up interference copies
	var result = _pool.erase(key)  # Remove the actual key
	_pool_mutex.unlock()
	return result

func clear():
	# COMPLETE DICTIONARY RESET:
	# Removes all data including interference patterns
	_pool_mutex.lock()
	_pool.clear()
	_pool_mutex.unlock()

func is_empty() -> bool:
	# CHECK IF DICTIONARY IS EMPTY:
	# Returns true only if no data exists (including interference)
	return _pool.is_empty()

# INTERFERENCE GENERATION SYSTEM:
# ================================
# The following functions implement the core anti-cheat mechanism by creating
# fake duplicate values that make memory scanning and modification extremely difficult.

# Process disturbances in the queue, ensuring only one is handled at a time
func _process_disturbance_queue():
	# QUEUE MANAGEMENT:
	# Limits concurrent interference threads to prevent resource exhaustion
	# while ensuring all values get their interference patterns generated
	if _disturb_threads.size() < 10 and _disturb_queue.size() > 0:  # Arbitrary limit
		var value = _disturb_queue.pop_front()
		_do_disturb(value)

func _do_disturb(value: ac_value):
	# INTERFERENCE THREAD SPAWNING:
	# Creates background thread to generate fake copies without blocking main thread
	# Each value gets its own interference pattern to maximize obfuscation
	
	if _disturb_threads.has(value):  # Prevent duplicate interference for the same value
		# print("Disturb already active for value: ", value)
		return
	if _disturb_threads.size() >= 10:  # Arbitrary limit to prevent resource exhaustion
		# print("Pool Size: ", _pool.size(), ". Too many disturbance threads running, skipping...")
		return

	# Spawn new background thread for interference generation
	var thread = Thread.new()
	_disturb_threads[value] = thread
	thread.start(_background_disturb.bind([thread, value]))

func _background_disturb(params: Array) -> void:
	# CORE ANTI-CHEAT INTERFERENCE GENERATION:
	# ========================================
	# This is where the actual anti-cheat magic happens!
	# Creates multiple fake copies of the real value with randomized keys.
	# 
	# ANTI-CHEAT STRATEGY:
	# If a cheater scans memory for a specific value (e.g., health = 100),
	# they'll find dozens of identical values instead of just one.
	# They won't know which one is the "real" value that actually affects gameplay.
	
	var thread: Thread = params[0]
	var value: ac_value = params[1]

	# Generate 'disturb' number of fake copies
	for i in range(disturb):
		_pool_mutex.lock()
		var salt = generate_salt()  # Random string to make each key unique
		# Store fake copy with special prefix: "__ac_disturb:[number][salt]__"
		# This naming convention allows us to identify and clean up interference data later
		_pool["__ac_disturb:%d__" % i + salt] = value.duplicate()
		_pool_mutex.unlock()

	# Notify main thread that interference generation is complete
	_on_disturb_complete.call_deferred(thread)

func _on_disturb_complete(thread: Thread):
	# THREAD CLEANUP AND QUEUE PROCESSING:
	# Clean up completed thread and start next interference task if queued
	if _disturb_threads.has(thread):
		thread.wait_to_finish()
		_disturb_threads.erase(thread)
		# print("Pool Size: " + str(_pool.size()) + ". Disturbance thread completed and cleaned up.")
	_process_disturbance_queue()  # Continue processing any remaining values in queue

func generate_salt() -> String:
	# RANDOMIZATION FOR INTERFERENCE KEYS:
	# Generates random 8-character strings to make interference keys unique.
	# This prevents patterns that cheaters could exploit to identify fake values.
	var rng = RandomNumberGenerator.new()
	var salt = ""
	for i in range(8):  # Generate an 8-character salt
		salt += String(char(rng.randi_range(65, 90)))  # Random uppercase letters (A-Z)
	return salt

# INTERFERENCE CLEANUP FUNCTIONS:
# ===============================
# These functions manage the lifecycle of interference data

func _quieten(value):
	# PARTIAL INTERFERENCE CLEANUP:
	# Removes excess interference copies while keeping some for continued protection.
	# This prevents memory usage from growing indefinitely while maintaining obfuscation.
	
	_pool_mutex.lock()
	var to_remove = []
	var count = 0
	
	# Find all interference keys for this value
	for wave in _pool:
		if wave.begins_with("__ac_disturb") and _pool.has(wave) and _pool[wave] == value:
			if count > disturb:
				# Mark excess copies for removal
				to_remove.append(wave)
				count+=1
			else:
				count+=1
	
	# Remove excess interference copies
	for key in to_remove:
		_pool.erase(key)
	_pool_mutex.unlock()
	
func _silence(value):
	# COMPLETE INTERFERENCE CLEANUP:
	# Removes ALL interference copies of a specific value.
	# Used when completely removing a value from the dictionary.
	
	var to_remove = []
	# Find all interference keys for this value
	for wave in _pool:
		if _pool[wave] == value and wave.begins_with("__ac_disturb"):
			to_remove.append(wave)
	
	# Remove all interference copies
	for horse in to_remove:
		_pool.erase(horse)
	
