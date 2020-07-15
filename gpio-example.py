#!/usr/bin/python

import RPi.GPIO as GPIO # Gpio library
from time import sleep # Time library required for sleep() method

PORT_A = 36 # 36 - number of gpio pin (see gpio-datasheet.jpg)
BUTTON_PIN = 40 # 40 - number of gpio pin (see gpio-datasheet.jpg)

# Initialization for gpio library
GPIO.setwarnings(False)
GPIO.setmode(GPIO.BOARD)

# Initialization for gpio inputs
GPIO.setup(PORT_A, GPIO.OUT)
GPIO.setup(BUTTON_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)

# Setting default values for pins
GPIO.output(PORT_A, 0)

# Main loop
while True:
    inp = GPIO.input(BUTTON_PIN) # If button pressed this parameter = 0
    
    # If button pressed run this code
    if inp == 0:
        GPIO.output(PORT_A, 1) # Start signal for pin #36
        sleep(2) # Wait wor 2 seconds
        GPIO.output(PORT_A, 0) # Stop signal for pin #36