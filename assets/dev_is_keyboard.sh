#!/bin/sh
DEVICE=$1
if evtest info $DEVICE | grep -q 'Event type 1 (Key)'; then
  if evtest info $DEVICE | grep -q 'Event code 16 (Q)'; then
    # Don't set these just because Key is supported -- that will
    # detect the touchscreen as a keyboard which breaks the UI
    echo ID_INPUT=1
    echo ID_INPUT_KEY=1
    echo ID_INPUT_KEYBOARD=1
  fi
fi
