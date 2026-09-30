# Copyright (c) 2026 froglike6. SPDX-License-Identifier: MIT
import json

import pytest
from fido2.ctap2.base import Ctap2
from fido2.server import Fido2Server
from fido2.utils import websafe_encode
from fido2.webauthn import (
    AttestationObject,
    AuthenticationResponse,
    AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse,
    CollectedClientData,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    RegistrationResponse,
    UserVerificationRequirement,
)

from transport import HostDevice


def test_server_accepts_registration_and_login_and_rejects_wrong_challenge(
    device: HostDevice,
) -> None:
    ctap = Ctap2(device)
    server = Fido2Server(PublicKeyCredentialRpEntity(id="example.com", name="Example"))
    options, registration_state = server.register_begin(
        PublicKeyCredentialUserEntity(id=b"alice", name="alice"),
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    client_data = CollectedClientData(json.dumps({
        "type": "webauthn.create", "challenge": websafe_encode(options.public_key.challenge),
        "origin": "https://example.com",
    }).encode())
    result = ctap.make_credential(
        client_data.hash, {"id": "example.com"}, {"id": b"alice"},
        [{"type": "public-key", "alg": -7}], options={"uv": True, "rk": True},
    )
    credential = result.auth_data.credential_data
    assert credential is not None
    registered = server.register_complete(
        registration_state, RegistrationResponse(
            raw_id=credential.credential_id,
            response=AuthenticatorAttestationResponse(
                client_data=client_data,
                attestation_object=AttestationObject.create(
                    result.fmt, result.auth_data, result.att_stmt,
                ),
            ),
        ),
    )
    assert registered.credential_data == credential
    login_options, login_state = server.authenticate_begin(
        [credential], user_verification=UserVerificationRequirement.REQUIRED,
    )
    login_data = CollectedClientData(json.dumps({
        "type": "webauthn.get", "challenge": websafe_encode(login_options.public_key.challenge),
        "origin": "https://example.com",
    }).encode())
    assertion = ctap.get_assertion("example.com", login_data.hash, options={"uv": True})
    response = AuthenticationResponse(
        raw_id=credential.credential_id,
        response=AuthenticatorAssertionResponse(
            client_data=login_data, authenticator_data=assertion.auth_data,
            signature=assertion.signature, user_handle=b"alice",
        ),
    )
    assert server.authenticate_complete(login_state, [credential], response) == credential
    _, wrong_state = server.authenticate_begin(
        [credential], user_verification=UserVerificationRequirement.REQUIRED,
    )
    with pytest.raises(ValueError, match="Wrong challenge"):
        _ = server.authenticate_complete(wrong_state, [credential], response)
