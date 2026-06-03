"""China-region Zeekr API helpers.

This module intentionally lives in the Home Assistant integration instead of
modifying ``zeekr_ev_api``.  The China mobile app uses an SMS-first login flow
while the upstream library currently models the overseas email/password flow.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import requests

try:
    from zeekr_ev_api import const, network, zeekr_hmac
    from zeekr_ev_api.client import ZeekrClient
    from zeekr_ev_api.exceptions import AuthException, ZeekrException
except ImportError:  # pragma: no cover - Home Assistant surfaces this at setup time
    const = network = zeekr_hmac = None  # type: ignore[assignment]
    ZeekrClient = object  # type: ignore[assignment,misc]

    class AuthException(Exception):
        """Fallback auth exception when zeekr_ev_api is not importable."""

    class ZeekrException(Exception):
        """Fallback API exception when zeekr_ev_api is not importable."""


CN_COUNTRY_CODE = "CN"
CN_REGION_CODE = "CN"
CN_API_HOST = "https://api-gw-toc.zeekrlife.com/"
CN_APP_SERVER_HOST = CN_API_HOST
CN_USERCENTER_HOST = CN_API_HOST
CN_MESSAGE_HOST = CN_API_HOST

# Endpoint names are based on the China app SMS authentication flow discussed by
# the community.  Some app versions prefix these routes differently, so the
# client tries each candidate until one returns a successful response.
CN_SEND_SMS_URLS = (
    "auth/sendSmsCode",
    "zeekr-cuc-idaas/auth/sendSmsCode",
    "usercenter/auth/sendSmsCode",
)
CN_LOGIN_BY_SMS_URLS = (
    "auth/loginBySms",
    "zeekr-cuc-idaas/auth/loginBySms",
    "usercenter/auth/loginBySms",
)
CN_REFRESH_TOKEN_URLS = (
    "auth/refreshToken",
    "zeekr-cuc-idaas/auth/refreshToken",
    "usercenter/auth/refreshToken",
)
CN_TSP_CODE_URLS = (
    "user/tspCode",
    "zeekr-cuc-idaas/user/tspCode",
    "usercenter/user/tspCode",
)
CN_USER_INFO_URLS = (
    "user/info",
    "zeekr-cuc-idaas/user/info",
    "usercenter/user/info",
)


class ZeekrChinaAuthError(AuthException):
    """Raised when the China SMS login flow fails."""


class ZeekrChinaSmsCodeError(ZeekrChinaAuthError):
    """Raised when the SMS code is rejected or expired."""


class ZeekrChinaClient(ZeekrClient):
    """Zeekr client variant for the mainland China SMS login flow."""

    def __init__(
        self,
        phone_number: str,
        sms_code: str | None = None,
        username: str | None = None,
        password: str | None = None,
        country_code: str = CN_COUNTRY_CODE,
        hmac_access_key: str = "",
        hmac_secret_key: str = "",
        password_public_key: str = "",
        prod_secret: str = "",
        vin_key: str = "",
        vin_iv: str = "",
        session_data: dict | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        # The parent constructor requires a password for a new session.  It is
        # never sent for China because this class overrides login().
        super().__init__(
            username=username or phone_number,
            password=password or "sms_login",
            country_code=country_code,
            hmac_access_key=hmac_access_key,
            hmac_secret_key=hmac_secret_key,
            password_public_key=password_public_key,
            prod_secret=prod_secret,
            vin_key=vin_key,
            vin_iv=vin_iv,
            session_data=session_data,
            logger=logger,
        )
        self.phone_number = phone_number
        self.sms_code = sms_code
        self.refresh_token: str | None = None
        self.country_code = CN_COUNTRY_CODE
        self.region_code = CN_REGION_CODE
        self.app_server_host = CN_APP_SERVER_HOST
        self.usercenter_host = CN_USERCENTER_HOST
        self.message_host = CN_MESSAGE_HOST
        self.region_login_server = CN_API_HOST
        self.logged_in_headers.update(
            {
                "ACCEPT-LANGUAGE": "zh-CN",
                "X-API-SIGNATURE-VERSION": "2.1",
                "X-PROJECT-ID": "ZEEKR_CN",
                "X-APP-ID": "ZEEKRCNCH001M0001",
            }
        )

    def login(self, relogin: bool = False) -> None:
        """Log in to the China API using phone number and SMS code."""
        if self.logged_in and not relogin:
            return
        self._configure_cn_hosts()
        if relogin and self.refresh_token:
            self._refresh_cn_auth_token()
        else:
            if not self.sms_code:
                raise ZeekrChinaSmsCodeError("SMS code is required for China login")
            self._do_sms_login_request()
        self._get_cn_user_info()
        tsp_code = self._get_cn_tsp_code()
        self._bearer_login(tsp_code)
        self.logged_in = True

    def send_sms_code(self) -> None:
        """Request an SMS verification code for the configured phone number."""
        self._configure_cn_hosts()
        payloads = (
            {"phone": self.phone_number, "countryCode": "86", "scene": "login"},
            {"mobile": self.phone_number, "countryCode": "86", "scene": "login"},
            {"phoneNumber": self.phone_number, "countryCode": "86", "type": "login"},
        )
        response = self._post_first_success(CN_SEND_SMS_URLS, payloads)
        if not self._is_success(response):
            raise ZeekrChinaAuthError(f"Unable to send SMS code: {response}")

    def _configure_cn_hosts(self) -> None:
        """Set static China API hosts and app-signature headers."""
        self.app_server_host = CN_APP_SERVER_HOST
        self.usercenter_host = CN_USERCENTER_HOST
        self.message_host = CN_MESSAGE_HOST
        self.region_code = CN_REGION_CODE
        self.region_login_server = CN_API_HOST
        self.logged_in_headers["X-API-SIGNATURE-VERSION"] = "2.1"
        self.logged_in_headers["X-PROJECT-ID"] = "ZEEKR_CN"
        self.logged_in_headers["ACCEPT-LANGUAGE"] = "zh-CN"

    def _do_sms_login_request(self) -> None:
        """Exchange phone number and SMS code for the user-center token."""
        payloads = (
            {"phone": self.phone_number, "smsCode": self.sms_code, "countryCode": "86"},
            {
                "mobile": self.phone_number,
                "smsCode": self.sms_code,
                "countryCode": "86",
            },
            {
                "phoneNumber": self.phone_number,
                "code": self.sms_code,
                "countryCode": "86",
            },
        )
        login_data = self._post_first_success(CN_LOGIN_BY_SMS_URLS, payloads)
        if not self._is_success(login_data):
            if self._looks_like_sms_code_error(login_data):
                raise ZeekrChinaSmsCodeError(
                    f"Invalid or expired SMS code: {login_data}"
                )
            raise ZeekrChinaAuthError(f"China SMS login failed: {login_data}")

        self._store_auth_tokens(login_data)

    def _refresh_cn_auth_token(self) -> None:
        """Refresh the China user-center token when a refresh token is available."""
        payloads = (
            {"refreshToken": self.refresh_token},
            {"refresh_token": self.refresh_token},
        )
        refresh_data = self._post_first_success(CN_REFRESH_TOKEN_URLS, payloads)
        if not self._is_success(refresh_data):
            raise ZeekrChinaAuthError(f"China token refresh failed: {refresh_data}")
        self._store_auth_tokens(refresh_data)

    def _store_auth_tokens(self, response: dict[str, Any]) -> None:
        """Store access and refresh tokens from China auth responses."""
        token = self._extract_token(response)
        if not token:
            raise ZeekrChinaAuthError(f"No auth token supplied in response: {response}")
        self.auth_token = token
        refresh_token = self._extract_refresh_token(response)
        if refresh_token:
            self.refresh_token = refresh_token
        self.session.headers["authorization"] = self.auth_token

    def _get_cn_user_info(self) -> None:
        """Fetch user information if the China user-center endpoint exposes it."""
        for path in CN_USER_INFO_URLS:
            try:
                response = self._signed_post(path)
            except Exception as err:  # pylint: disable=broad-except
                self.logger.debug("China user info endpoint %s failed: %s", path, err)
                continue
            if self._is_success(response):
                self.user_info = response.get("data", {}) or {}
                return

    def _get_cn_tsp_code(self) -> str:
        """Fetch the TSP code needed by the existing bearer-login flow."""
        client_id = const.DEFAULT_HEADERS.get("client-id", "")
        for path in CN_TSP_CODE_URLS:
            separator = "&" if "?" in path else "?"
            response = self._signed_get(f"{path}{separator}tspClientId={client_id}")
            if self._is_success(response):
                code = (response.get("data") or {}).get("code")
                if code:
                    return code
        raise ZeekrException("Unable to fetch China TSP code")

    def _post_first_success(
        self, paths: tuple[str, ...], payloads: tuple[dict[str, Any], ...]
    ) -> dict[str, Any]:
        """Try endpoint/payload combinations and return the first success."""
        last_response: dict[str, Any] = {}
        for path in paths:
            for payload in payloads:
                try:
                    response = self._signed_post(path, payload)
                except Exception as err:  # pylint: disable=broad-except
                    self.logger.debug("China auth endpoint %s failed: %s", path, err)
                    continue
                last_response = response
                if self._is_success(response):
                    return response
                if self._looks_like_sms_code_error(response):
                    return response
        return last_response

    def _signed_post(
        self, path: str, body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        req = requests.Request(
            "POST",
            self._cn_url(path),
            headers=self._cn_default_headers(),
            json=body or {},
        )
        return self._send_hmac_request(req)

    def _signed_get(self, path: str) -> dict[str, Any]:
        req = requests.Request(
            "GET", self._cn_url(path), headers=self._cn_default_headers()
        )
        return self._send_hmac_request(req)

    @staticmethod
    def _cn_url(path: str) -> str:
        return f"{CN_API_HOST}{path.lstrip('/')}"

    @staticmethod
    def _cn_default_headers() -> dict[str, str]:
        headers = const.DEFAULT_HEADERS.copy()
        headers.update(
            {
                "accept-language": "zh-CN",
                "country": CN_COUNTRY_CODE,
                "registcountry": CN_COUNTRY_CODE,
            }
        )
        return headers

    def _send_hmac_request(self, req: requests.Request) -> dict[str, Any]:
        signed = zeekr_hmac.generateHMAC(
            req, self.hmac_access_key, self.hmac_secret_key
        )
        prepped = self.session.prepare_request(signed)
        resp = self.session.send(prepped)
        return network._safe_json(resp, self.logger)  # pylint: disable=protected-access

    @staticmethod
    def _is_success(response: dict[str, Any]) -> bool:
        return bool(
            response.get("success") is True
            or response.get("code") in (0, "0", "000000")
        )

    @staticmethod
    def _extract_token(response: dict[str, Any]) -> str | None:
        data = response.get("data") or {}
        if isinstance(data, str):
            return data
        for key in ("tokenValue", "accessToken", "access_token", "token", "idToken"):
            token = data.get(key)
            if token:
                return token
        token_info = data.get("token")
        if isinstance(token_info, dict):
            for key in ("tokenValue", "accessToken", "access_token"):
                token = token_info.get(key)
                if token:
                    return token
        return None

    @staticmethod
    def _extract_refresh_token(response: dict[str, Any]) -> str | None:
        data = response.get("data") or {}
        if not isinstance(data, dict):
            return None
        for key in ("refreshToken", "refresh_token"):
            token = data.get(key)
            if token:
                return token
        token_info = data.get("token")
        if isinstance(token_info, dict):
            for key in ("refreshToken", "refresh_token"):
                token = token_info.get(key)
                if token:
                    return token
        return None

    @staticmethod
    def _looks_like_sms_code_error(response: dict[str, Any]) -> bool:
        text = json.dumps(response, ensure_ascii=False).lower()
        return any(
            marker in text
            for marker in (
                "sms",
                "验证码",
                "verification code",
                "verify code",
                "expired",
                "invalid code",
                "code error",
            )
        )
