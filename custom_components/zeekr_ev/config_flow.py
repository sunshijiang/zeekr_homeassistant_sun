"""Adds config flow for Zeekr EV API Integration."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.helpers import selector

from .api import CN_COUNTRY_CODE, ZeekrChinaClient, ZeekrChinaSmsCodeError
from .const import (
    CONF_COUNTRY_CODE,
    CONF_DRIVE_SIDE,
    CONF_HMAC_ACCESS_KEY,
    CONF_HMAC_SECRET_KEY,
    CONF_PASSWORD,
    CONF_PASSWORD_PUBLIC_KEY,
    CONF_PHONE_NUMBER,
    CONF_POLLING_INTERVAL,
    CONF_PROD_SECRET,
    CONF_SMS_CODE,
    CONF_USERNAME,
    CONF_USE_LOCAL_API,
    CONF_VIN_IV,
    CONF_VIN_KEY,
    COUNTRY_CODE_MAPPING,
    DEFAULT_POLLING_INTERVAL,
    DOMAIN,
    DRIVE_SIDE_LHD,
    DRIVE_SIDE_RHD,
)
from .utils import get_zeekr_client_class, validate_input

_LOGGER = logging.getLogger(__name__)


def _is_cn(data: dict[str, Any]) -> bool:
    """Return whether the selected region is mainland China."""
    return data.get(CONF_COUNTRY_CODE) == CN_COUNTRY_CODE


def _strip_input(user_input: dict[str, Any]) -> None:
    """Trim whitespace from all string fields in-place."""
    for key, value in list(user_input.items()):
        if isinstance(value, str):
            user_input[key] = value.strip()


def _country_selector(defaults: dict[str, Any]) -> selector.SelectSelector:
    """Build the country selector including the China region."""
    return selector.SelectSelector(
        selector.SelectSelectorConfig(
            options=[
                selector.SelectOptionDict(value=code, label=f"{name} ({code})")
                for code, (name, _) in COUNTRY_CODE_MAPPING.items()
            ]
        )
    )


def _drive_side_selector() -> selector.SelectSelector:
    """Build the drive-side selector."""
    return selector.SelectSelector(
        selector.SelectSelectorConfig(
            options=[
                selector.SelectOptionDict(
                    value=DRIVE_SIDE_LHD, label="Left-Hand Drive (LHD)"
                ),
                selector.SelectOptionDict(
                    value=DRIVE_SIDE_RHD, label="Right-Hand Drive (RHD)"
                ),
            ]
        )
    )


def _secret_selector() -> selector.TextSelector:
    """Return a password-style text selector for secret values."""
    return selector.TextSelector(
        selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
    )


def _build_schema(
    defaults: dict[str, Any], *, include_sms_code: bool = False
) -> vol.Schema:
    """Build a config schema, hiding password for China SMS login."""
    cn_region = _is_cn(defaults)
    schema: dict[Any, Any] = {
        vol.Optional(
            CONF_COUNTRY_CODE, default=defaults.get(CONF_COUNTRY_CODE, "AU")
        ): _country_selector(defaults),
    }

    if cn_region:
        schema[
            vol.Required(CONF_PHONE_NUMBER, default=defaults.get(CONF_PHONE_NUMBER, ""))
        ] = str
        schema[
            vol.Optional(
                CONF_USERNAME,
                default=defaults.get(
                    CONF_USERNAME, defaults.get(CONF_PHONE_NUMBER, "")
                ),
            )
        ] = str
        if include_sms_code:
            schema[
                vol.Required(CONF_SMS_CODE, default=defaults.get(CONF_SMS_CODE, ""))
            ] = str
    else:
        schema[vol.Required(CONF_USERNAME, default=defaults.get(CONF_USERNAME, ""))] = (
            str
        )
        schema[vol.Required(CONF_PASSWORD, default=defaults.get(CONF_PASSWORD, ""))] = (
            _secret_selector()
        )

    schema.update(
        {
            vol.Optional(
                CONF_POLLING_INTERVAL,
                default=defaults.get(CONF_POLLING_INTERVAL, DEFAULT_POLLING_INTERVAL),
            ): int,
            vol.Optional(
                CONF_HMAC_ACCESS_KEY, default=defaults.get(CONF_HMAC_ACCESS_KEY, "")
            ): _secret_selector(),
            vol.Optional(
                CONF_HMAC_SECRET_KEY, default=defaults.get(CONF_HMAC_SECRET_KEY, "")
            ): _secret_selector(),
            vol.Optional(
                CONF_PASSWORD_PUBLIC_KEY,
                default=defaults.get(CONF_PASSWORD_PUBLIC_KEY, ""),
            ): str,
            vol.Optional(
                CONF_PROD_SECRET, default=defaults.get(CONF_PROD_SECRET, "")
            ): str,
            vol.Optional(
                CONF_VIN_KEY, default=defaults.get(CONF_VIN_KEY, "")
            ): _secret_selector(),
            vol.Optional(
                CONF_VIN_IV, default=defaults.get(CONF_VIN_IV, "")
            ): _secret_selector(),
            vol.Optional(
                CONF_USE_LOCAL_API, default=defaults.get(CONF_USE_LOCAL_API, False)
            ): selector.BooleanSelector(),
            vol.Optional(
                CONF_DRIVE_SIDE, default=defaults.get(CONF_DRIVE_SIDE, DRIVE_SIDE_LHD)
            ): _drive_side_selector(),
        }
    )
    return vol.Schema(schema)


def _validate_required(user_input: dict[str, Any]) -> str | None:
    """Validate fields that are always required for the selected auth mode."""
    _strip_input(user_input)
    if _is_cn(user_input):
        if not user_input.get(CONF_PHONE_NUMBER):
            return "phone_required"
        # China does not need the RSA password public key because no password is sent.
        cn_input = dict(user_input)
        cn_input.pop(CONF_PASSWORD_PUBLIC_KEY, None)
        return validate_input(cn_input)

    if not user_input.get(CONF_USERNAME) or not user_input.get(CONF_PASSWORD):
        return "auth"
    return validate_input(user_input)


class ZeekrEVAPIFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):  # type: ignore[call-arg]
    """Config flow for zeekr_ev_api_integration."""

    VERSION = 1
    CONNECTION_CLASS = config_entries.CONN_CLASS_CLOUD_POLL

    def __init__(self) -> None:
        """Initialize."""
        self._errors: dict[str, str] = {}
        self._temp_client = None
        self._cn_pending_input: dict[str, Any] | None = None

    async def async_step_user(self, user_input=None):
        """Handle a flow initialized by the user."""
        self._errors = {}

        if user_input is not None:
            validation_error = _validate_required(user_input)
            if validation_error:
                self._errors["base"] = validation_error
                return await self._show_config_form(user_input)

            if _is_cn(user_input):
                return await self._handle_cn_initial(user_input)

            valid = await self._test_credentials(
                user_input[CONF_USERNAME],
                user_input[CONF_PASSWORD],
                user_input[CONF_COUNTRY_CODE],
                user_input[CONF_HMAC_ACCESS_KEY],
                user_input[CONF_HMAC_SECRET_KEY],
                user_input[CONF_PASSWORD_PUBLIC_KEY],
                user_input[CONF_PROD_SECRET],
                user_input[CONF_VIN_KEY],
                user_input[CONF_VIN_IV],
                user_input.get(CONF_USE_LOCAL_API, False),
            )
            if valid:
                self.hass.data.setdefault(DOMAIN, {})[
                    "_temp_client"
                ] = self._temp_client
                return self.async_create_entry(
                    title=user_input[CONF_USERNAME], data=user_input
                )
            self._errors["base"] = "auth"
            return await self._show_config_form(user_input)

        return await self._show_config_form(user_input)

    async def async_step_cn_sms(self, user_input=None):
        """Validate the China SMS code and create the config entry."""
        self._errors = {}
        if self._cn_pending_input is None:
            return await self.async_step_user()

        data = dict(self._cn_pending_input)
        if user_input:
            data.update(user_input)
            _strip_input(data)
            if not data.get(CONF_SMS_CODE):
                self._errors["base"] = "sms_code_required"
            else:
                valid = await self._test_cn_credentials(data)
                if valid:
                    data[CONF_USERNAME] = (
                        data.get(CONF_USERNAME) or data[CONF_PHONE_NUMBER]
                    )
                    data[CONF_PASSWORD] = ""
                    self.hass.data.setdefault(DOMAIN, {})[
                        "_temp_client"
                    ] = self._temp_client
                    return self.async_create_entry(
                        title=data[CONF_PHONE_NUMBER], data=data
                    )
                if "base" not in self._errors:
                    self._errors["base"] = "sms_code_invalid"

        return self.async_show_form(
            step_id="cn_sms",
            data_schema=_build_schema(data, include_sms_code=True),
            errors=self._errors,
        )

    async def _handle_cn_initial(self, user_input: dict[str, Any]):
        """Send an SMS code before collecting the verification code."""
        self._cn_pending_input = dict(user_input)
        try:
            await self.hass.async_add_executor_job(self._send_cn_sms_code, user_input)
        except Exception as err:  # pylint: disable=broad-except
            _LOGGER.warning("Unable to send Zeekr China SMS code: %s", err)
            self._errors["base"] = "sms_send_failed"
            return await self._show_config_form(user_input)
        return await self.async_step_cn_sms()

    def _send_cn_sms_code(self, user_input: dict[str, Any]) -> None:
        client = ZeekrChinaClient(
            phone_number=user_input[CONF_PHONE_NUMBER],
            username=user_input.get(CONF_USERNAME) or user_input[CONF_PHONE_NUMBER],
            country_code=CN_COUNTRY_CODE,
            hmac_access_key=user_input.get(CONF_HMAC_ACCESS_KEY, ""),
            hmac_secret_key=user_input.get(CONF_HMAC_SECRET_KEY, ""),
            password_public_key=user_input.get(CONF_PASSWORD_PUBLIC_KEY, ""),
            prod_secret=user_input.get(CONF_PROD_SECRET, ""),
            vin_key=user_input.get(CONF_VIN_KEY, ""),
            vin_iv=user_input.get(CONF_VIN_IV, ""),
            logger=_LOGGER,
        )
        client.send_sms_code()

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return ZeekrEVAPIOptionsFlowHandler(config_entry)

    async def _show_config_form(self, user_input):
        """Show the configuration form."""
        return self.async_show_form(
            step_id="user",
            data_schema=_build_schema(user_input or {}),
            errors=self._errors,
        )

    async def _test_credentials(
        self,
        username,
        password,
        country_code,
        hmac_access_key,
        hmac_secret_key,
        password_public_key,
        prod_secret,
        vin_key,
        vin_iv,
        use_local_api=False,
    ):
        """Return true if credentials is valid."""
        try:
            ZeekrClient = await self.hass.async_add_executor_job(
                get_zeekr_client_class, use_local_api
            )
            client = ZeekrClient(
                username=username,
                password=password,
                country_code=country_code,
                hmac_access_key=hmac_access_key,
                hmac_secret_key=hmac_secret_key,
                password_public_key=password_public_key,
                prod_secret=prod_secret,
                vin_key=vin_key,
                vin_iv=vin_iv,
                logger=_LOGGER,
            )
            await self.hass.async_add_executor_job(client.login)
            self._temp_client = client
        except Exception:  # pylint: disable=broad-except
            return False
        return True

    async def _test_cn_credentials(self, data: dict[str, Any]) -> bool:
        """Return true if China SMS credentials are valid."""
        try:
            client = ZeekrChinaClient(
                phone_number=data[CONF_PHONE_NUMBER],
                sms_code=data[CONF_SMS_CODE],
                username=data.get(CONF_USERNAME) or data[CONF_PHONE_NUMBER],
                country_code=CN_COUNTRY_CODE,
                hmac_access_key=data.get(CONF_HMAC_ACCESS_KEY, ""),
                hmac_secret_key=data.get(CONF_HMAC_SECRET_KEY, ""),
                password_public_key=data.get(CONF_PASSWORD_PUBLIC_KEY, ""),
                prod_secret=data.get(CONF_PROD_SECRET, ""),
                vin_key=data.get(CONF_VIN_KEY, ""),
                vin_iv=data.get(CONF_VIN_IV, ""),
                logger=_LOGGER,
            )
            await self.hass.async_add_executor_job(client.login)
            self._temp_client = client
        except ZeekrChinaSmsCodeError:
            self._errors["base"] = "sms_code_invalid"
            return False
        except Exception:  # pylint: disable=broad-except
            return False
        return True


class ZeekrEVAPIOptionsFlowHandler(config_entries.OptionsFlow):
    """Config flow options handler for zeekr_ev_api_integration."""

    def __init__(self, config_entry):
        """Initialize options flow."""
        self._config_entry = config_entry

    async def async_step_init(self, user_input=None):  # pylint: disable=unused-argument
        """Manage the options."""
        return await self.async_step_user()

    async def async_step_user(self, user_input=None):
        """Handle an options flow."""
        errors: dict[str, str] = {}
        data = {**self._config_entry.data}

        if user_input is not None:
            merged = {**data, **user_input}
            validation_error = _validate_required(merged)
            if validation_error:
                errors["base"] = validation_error
            else:
                needs_auth = any(
                    merged.get(key) != data.get(key)
                    for key in (
                        CONF_USERNAME,
                        CONF_PASSWORD,
                        CONF_PHONE_NUMBER,
                        CONF_SMS_CODE,
                        CONF_COUNTRY_CODE,
                        CONF_HMAC_ACCESS_KEY,
                        CONF_HMAC_SECRET_KEY,
                        CONF_PASSWORD_PUBLIC_KEY,
                        CONF_PROD_SECRET,
                        CONF_VIN_KEY,
                        CONF_VIN_IV,
                        CONF_USE_LOCAL_API,
                    )
                )
                if needs_auth and not _is_cn(merged):
                    valid = await self._test_credentials(
                        merged.get(CONF_USERNAME),
                        merged.get(CONF_PASSWORD),
                        merged.get(CONF_COUNTRY_CODE, ""),
                        merged.get(CONF_HMAC_ACCESS_KEY, ""),
                        merged.get(CONF_HMAC_SECRET_KEY, ""),
                        merged.get(CONF_PASSWORD_PUBLIC_KEY, ""),
                        merged.get(CONF_PROD_SECRET, ""),
                        merged.get(CONF_VIN_KEY, ""),
                        merged.get(CONF_VIN_IV, ""),
                        merged.get(CONF_USE_LOCAL_API, False),
                    )
                    if not valid:
                        errors["base"] = "auth"
                elif needs_auth and _is_cn(merged) and not merged.get(CONF_SMS_CODE):
                    errors["base"] = "sms_code_required"

                if not errors:
                    if _is_cn(merged):
                        merged[CONF_USERNAME] = merged.get(CONF_USERNAME) or merged.get(
                            CONF_PHONE_NUMBER
                        )
                        merged[CONF_PASSWORD] = ""
                    self.hass.config_entries.async_update_entry(
                        self._config_entry, data=merged
                    )
                    await self.hass.config_entries.async_reload(
                        self._config_entry.entry_id
                    )
                    return self.async_abort(reason="reconfigure_successful")

        return self.async_show_form(
            step_id="user",
            data_schema=_build_schema(
                {**data, **(user_input or {})},
                include_sms_code=_is_cn({**data, **(user_input or {})}),
            ),
            errors=errors,
        )

    async def _test_credentials(
        self,
        username,
        password,
        country_code,
        hmac_access_key,
        hmac_secret_key,
        password_public_key,
        prod_secret,
        vin_key,
        vin_iv,
        use_local_api=False,
    ):
        """Return true if credentials are valid."""
        try:
            ZeekrClient = await self.hass.async_add_executor_job(
                get_zeekr_client_class, use_local_api
            )
            client = ZeekrClient(
                username=username,
                password=password,
                country_code=country_code,
                hmac_access_key=hmac_access_key,
                hmac_secret_key=hmac_secret_key,
                password_public_key=password_public_key,
                prod_secret=prod_secret,
                vin_key=vin_key,
                vin_iv=vin_iv,
                logger=_LOGGER,
            )
            await self.hass.async_add_executor_job(client.login)
        except Exception:  # pylint: disable=broad-except
            return False
        return True
