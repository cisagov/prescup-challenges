
# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from tensorflow import keras
from tensorflow.keras import Sequential
from tensorflow.keras.layers import Dense
import numpy as numpy

denseNerualLayer = Dense(units=1, input_shape=[1])
#model = Sequential([Dense(units=1, input_shape=[1])])
mod = Sequential([denseNerualLayer])
mod.compile(optimizer='sgd', loss='mean_squared_error')

#Y = 27X - 5
waypoints1 = numpy.array([1.0, 3.0, 5.0, 7.0, 11.0], dtype=float)
waypoints2a = numpy.array([22.0, 76.0, 130.0, 184.0, 292.0], dtype=float)

#Y = 19X - 4
waypoints2b = numpy.array([15.0, 53.0, 91.0, 129.0, 205.0], dtype=float)

#Y = 21X - 2
waypoints2c = numpy.array([19.0, 61.0, 103.0, 145.0, 229.0], dtype=float)

mod.fit(waypoints1, waypoints2a, epochs=1000)

print("")
print("Model Summary")
mod.summary()
print("")
print("Weights:")
print(denseNerualLayer.get_weights())
