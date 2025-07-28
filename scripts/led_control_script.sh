#!/bin/sh
#Script to control the xle led
#for XLE only
both_led_off()
{
        echo none > /sys/class/leds/RED/trigger
        echo 255 > /sys/class/leds/RED/brightness
        echo none > /sys/class/leds/WHITE/trigger
        echo 255 > /sys/class/leds/WHITE/brightness
}
led_solid() {
    if [ "$1" == "RED" ] || [ "$1" == "WHITE" ];then
        echo "led_solid $1"
        both_led_off
        echo none > /sys/class/leds/$1/trigger
        echo 0 > /sys/class/leds/$1/brightness

    elif [ "$1" == "OFF" ];then
        both_led_off
        echo "led_off"
    else
        echo "wrong command"
    fi
}

led_slow_blink() {
    if [ "$1" == "RED" ] || [ "$1" == "WHITE" ];then
        echo "led_slow_blink $1"
        both_led_off
        echo timer > /sys/class/leds/$1/trigger
        echo 1000 > /sys/class/leds/$1/delay_on
        echo 1000 > /sys/class/leds/$1/delay_off
    else
        echo "wrong command"
    fi
}

led_flash_blink() {
    if [ "$1" == "RED" ] || [ "$1" == "WHITE" ];then
        echo "led_flash_blink $1"
        both_led_off
        echo timer > /sys/class/leds/$1/trigger
        echo 500 > /sys/class/leds/$1/delay_on
        echo 500 > /sys/class/leds/$1/delay_off
    else
        echo "wrong command"
    fi
}

action() {
    case "$1" in
        "SOLID")
            led_solid $2
            RET=$?
            ;;

        "BLINK_SLOW")
            led_slow_blink $2
            RET=$?
            ;;

        "BLINK_FAST")
            led_flash_blink $2
            RET=$?
            ;;


        *)
            echo "Usage: $0 {SOLID|BLINK_SLOW|BLINK_FAST} {OFF|RED|WHITE}"
            RET=1
            ;;

    esac

    return $RET
}

action "$1" "$2"
