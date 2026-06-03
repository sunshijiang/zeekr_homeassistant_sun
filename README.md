# Zeekr EV Integration for Home Assistant

This is a custom integration for Zeekr Electric Vehicles for Home Assistant. It uses the [zeekr_ev_api](https://github.com/Fryyyyy/zeekr_ev_api) library.

## Features

- **Climate**: Control Heating / Cooling Vents & Seats and Steering Wheel.
- **Sensors**: Battery Level, Range, Odometer, Interior Temperature, Tire Pressures, Charging Power, Voltage, Speed.
- **Binary Sensors**: Charging Status, Plugged In Status, Doors, Tyre Warnings.
- **Buttons**: Flash blinkers, enable/disable Sentry Mode.
- **Locks**: Door and Trunk Lock.
- **Device Tracker**: Location tracking.

## Installation

### HACS

1. Open HACS.
2. Add this repository as a custom repository (Integration).
3. Search for "Zeekr EV Integration" and install.
4. Restart Home Assistant.

### Manual

1. Copy the `custom_components/zeekr_ev` folder to your Home Assistant `config/custom_components/` directory.
2. Restart Home Assistant.

## Configuration

1. Go to Settings -> Devices & Services.
2. Click "Add Integration".
3. Search for "Zeekr EV".
4. Select your region and enter the requested credentials.

### Overseas regions (EU/SEA/EM and others)

Overseas regions continue to use the existing `username` + `password` login flow supplied by `zeekr_ev_api`.

### Mainland China (CN) SMS login

China-region Zeekr accounts do not expose a password login in the China app. Select **China (CN)** as the country/region, then enter:

- `phone_number`: the mainland China mobile number bound to the Zeekr account.
- `hmac_access_key` and `hmac_secret_key`: keys extracted from the China app, for example with `wysie/zeekr_key_extractor`.
- Existing vehicle/signature secrets such as `prod_secret`, `vin_key`, and `vin_iv`. The password field is hidden for CN because it is not used.

Submit the form once to request a verification SMS from `https://api-gw-toc.zeekrlife.com/`, then enter the received `sms_code` when Home Assistant shows the SMS-code step. The integration signs China authentication requests with the extracted HMAC keys and uses app-signature header version `2.1` for China API calls.

If Zeekr reports that the verification code is invalid or expired, request a new SMS code and retry. If the account is kicked out on another phone, use a dedicated sub-account shared to the vehicle for Home Assistant.

## Tips & Tricks

- **Account**: Create a new account and share your car with the new account to avoid "The account is currently logged in elsewhere"
- **Secrets**: Get the secrets by decompiling the Android app.
- **Display**: Use vehicle-status-card for a good quality dashboard.

## Issues

Please report issues on the [GitHub Issue Tracker](https://github.com/Fryyyyy/zeekr_homeassistant/issues).
