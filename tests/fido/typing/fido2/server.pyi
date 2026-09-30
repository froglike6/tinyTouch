# Copyright (c) 2026 froglike6. SPDX-License-Identifier: MIT
# Typed test surface for the pinned python-fido2 2.1.1 server API.

from collections.abc import Callable, Sequence
from typing import TypedDict

from fido2.webauthn import (
    AttestationConveyancePreference,
    AttestationObject,
    AttestedCredentialData,
    AuthenticationResponse,
    AuthenticatorAttachment,
    AuthenticatorData,
    CredentialCreationOptions,
    CredentialRequestOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    RegistrationResponse,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

class ServerState(TypedDict):
    # The two fields returned by Fido2Server._make_internal_state.

    challenge: str
    user_verification: UserVerificationRequirement | None

class Fido2Server:
    # Signatures used here retain the upstream implementation at runtime.

    def __init__(
        self, rp: PublicKeyCredentialRpEntity,
        attestation: AttestationConveyancePreference | None = None,
        verify_origin: Callable[[str], bool] | None = None,
        verify_attestation: Callable[[AttestationObject, bytes], None] | None = None,
    ) -> None: ...
    def register_begin(
        self, user: PublicKeyCredentialUserEntity,
        credentials: Sequence[AttestedCredentialData | PublicKeyCredentialDescriptor] | None = None,
        resident_key_requirement: ResidentKeyRequirement | None = None,
        user_verification: UserVerificationRequirement | None = None,
        authenticator_attachment: AuthenticatorAttachment | None = None,
        challenge: bytes | None = None,
    ) -> tuple[CredentialCreationOptions, ServerState]: ...
    def register_complete(
        self, state: ServerState, response: RegistrationResponse,
    ) -> AuthenticatorData: ...
    def authenticate_begin(
        self,
        credentials: Sequence[AttestedCredentialData | PublicKeyCredentialDescriptor] | None = None,
        user_verification: UserVerificationRequirement | None = None,
        challenge: bytes | None = None,
    ) -> tuple[CredentialRequestOptions, ServerState]: ...
    def authenticate_complete(
        self, state: ServerState, credentials: Sequence[AttestedCredentialData],
        response: AuthenticationResponse,
    ) -> AttestedCredentialData: ...
