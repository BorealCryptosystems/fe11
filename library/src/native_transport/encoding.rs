// SPDX-License-Identifier: Apache-2.0
//! Encode typed transport parameters into native ABI fields and input graphs.
//! Scalar widths, pointer extents and nested OAEP storage are bound before dispatch.

use super::*;

impl<'a> Recipe<'a> {
    pub(super) fn new() -> Self {
        Self {
            root: [0; size_of::<CK_SKIPJACK_RELAYX_PARAMS>()],
            nested: [0; size_of::<CK_RSA_PKCS_OAEP_PARAMS>()],
            length: 0,
            raw_root: None,
            fields: [(0, None, ExtensionDirection::Input); 8],
            count: 0,
            nested_oaep: false,
            source: None,
            assertion: None,
        }
    }

    pub(super) fn scalar(&mut self, offset: usize, value: u64) -> Result<()> {
        scalar(&mut self.root, offset, value)
    }

    pub(super) fn input(
        &mut self,
        pointer: usize,
        length: usize,
        bytes: Option<&'a [u8]>,
    ) -> Result<()> {
        self.scalar(length, bytes.map_or(0, |b| b.len()) as u64)?;
        self.pointer(pointer, bytes, ExtensionDirection::Input);
        Ok(())
    }

    pub(super) fn pointer(
        &mut self,
        offset: usize,
        bytes: Option<&'a [u8]>,
        direction: ExtensionDirection,
    ) {
        // Every call site is a closed standard layout with at most seven pointers.
        self.fields[self.count] = (offset, bytes, direction);
        self.count += 1;
    }

    pub(super) fn oaep(&mut self, value: NativeOaepParameters<'a>, nested: bool) -> Result<()> {
        let raw: &mut [u8] = if nested {
            &mut self.nested
        } else {
            &mut self.root
        };
        scalar(
            raw,
            offset_of!(CK_RSA_PKCS_OAEP_PARAMS, hashAlg),
            value.hash,
        )?;
        scalar(raw, offset_of!(CK_RSA_PKCS_OAEP_PARAMS, mgf), value.mgf)?;
        scalar(
            raw,
            offset_of!(CK_RSA_PKCS_OAEP_PARAMS, source),
            value.source,
        )?;
        scalar(
            raw,
            offset_of!(CK_RSA_PKCS_OAEP_PARAMS, ulSourceDataLen),
            value.data.map_or(0, |b| b.len()) as u64,
        )?;
        self.nested_oaep = nested;
        self.pointer(
            offset_of!(CK_RSA_PKCS_OAEP_PARAMS, pSourceData),
            value.data,
            ExtensionDirection::Input,
        );
        Ok(())
    }

    pub(super) fn invoke<T>(
        self,
        session: &Session,
        kind: CK_MECHANISM_TYPE,
        operation: ExtensionOperation,
        execute: impl FnOnce(ExtensionRequest<'_>, ParameterKeys<'a>) -> Result<T>,
    ) -> Result<T> {
        let standard = MechanismExtension::standard(&session.inner, kind, operation);
        let contract = match self.assertion {
            Some(contract) => {
                contract.check(&session.inner, operation)?;
                if contract.mechanism_number() != kind as u64 {
                    return Err(Error::Rejected(crate::RejectionReason::NativeTransport(
                        crate::NativeTransportRejection::HistoricalTransportMechanismLayoutMismatch,
                    )));
                }
                contract
            }
            None => &standard,
        };
        if let Some(raw) = self.raw_root {
            let blocks = [ExtensionBlock {
                initial: raw.unwrap_or(&[]),
                alignment: 1,
                direction: ExtensionDirection::Input,
            }];
            return execute(
                ExtensionRequest {
                    contract,
                    parameters: ExtensionParameters {
                        blocks: if raw.is_some() { &blocks } else { &[] },
                        pointers: &[],
                        root: raw.map(|_| 0),
                        outputs: &[],
                    },
                },
                ParameterKeys::from_source(self.source),
            );
        }
        let mut blocks: [ExtensionBlock<'_>; 10] = std::array::from_fn(|_| ExtensionBlock {
            initial: &[],
            alignment: 1,
            direction: ExtensionDirection::Input,
        });
        blocks[0] = ExtensionBlock {
            initial: &self.root[..self.length],
            alignment: align_of::<CK_ULONG>(),
            direction: ExtensionDirection::Input,
        };
        let mut pointers: [ExtensionPointer; 9] = std::array::from_fn(|_| ExtensionPointer {
            block: 0,
            offset: 0,
            target: ExtensionPointerTarget::Null,
        });
        let mut outputs = [ExtensionOutputRegion {
            block: 0,
            offset: 0,
            capacity: 0,
            length: ExtensionOutputLength::Fixed,
        }; 8];
        let mut block_count = 1;
        let mut pointer_count = 0;
        let mut output_count = 0;
        if self.nested_oaep {
            blocks[1] = ExtensionBlock {
                initial: &self.nested,
                alignment: align_of::<CK_RSA_PKCS_OAEP_PARAMS>(),
                direction: ExtensionDirection::Input,
            };
            block_count += 1;
            pointers[0] = ExtensionPointer {
                block: 0,
                offset: offset_of!(CK_RSA_AES_KEY_WRAP_PARAMS, pOAEPParams),
                target: ExtensionPointerTarget::Block {
                    block: 1,
                    offset: 0,
                },
            };
            pointer_count += 1;
        }
        for &(offset, bytes, direction) in &self.fields[..self.count] {
            let target = if let Some(bytes) = bytes {
                let block = block_count;
                blocks[block] = ExtensionBlock {
                    initial: bytes,
                    alignment: 1,
                    direction,
                };
                block_count += 1;
                if direction != ExtensionDirection::Input {
                    outputs[output_count] = ExtensionOutputRegion {
                        block,
                        offset: 0,
                        capacity: bytes.len(),
                        length: ExtensionOutputLength::Fixed,
                    };
                    output_count += 1;
                }
                ExtensionPointerTarget::Block { block, offset: 0 }
            } else {
                ExtensionPointerTarget::Null
            };
            pointers[pointer_count] = ExtensionPointer {
                block: usize::from(self.nested_oaep),
                offset,
                target,
            };
            pointer_count += 1;
        }
        execute(
            ExtensionRequest {
                contract,
                parameters: ExtensionParameters {
                    blocks: &blocks[..block_count],
                    pointers: &pointers[..pointer_count],
                    root: Some(0),
                    outputs: &outputs[..output_count],
                },
            },
            ParameterKeys::from_source(self.source),
        )
    }
}

pub(super) fn scalar(raw: &mut [u8], offset: usize, value: u64) -> Result<()> {
    let value = CK_ULONG::try_from(value).map_err(|_| {
        Error::Rejected(crate::RejectionReason::NativeTransport(
            crate::NativeTransportRejection::TransportScalarAbiWidth,
        ))
    })?;
    raw[offset..offset + size_of::<CK_ULONG>()].copy_from_slice(&value.to_ne_bytes());
    Ok(())
}

pub(crate) fn with_parameters<'a, T>(
    session: &Session,
    parameters: NativeTransportParameters<'a>,
    operation: ExtensionOperation,
    execute: impl FnOnce(ExtensionRequest<'_>, [Option<&'a NativeObjectRef>; 4]) -> Result<T>,
) -> Result<T> {
    with_bound_parameters(session, parameters, operation, |request, keys| {
        execute(request, keys.references()?)
    })
}

pub(crate) fn with_bound_parameters<'a, T>(
    session: &Session,
    parameters: NativeTransportParameters<'a>,
    operation: ExtensionOperation,
    execute: impl FnOnce(ExtensionRequest<'_>, ParameterKeys<'a>) -> Result<T>,
) -> Result<T> {
    let (kind, recipe) = encode(parameters, operation)?;
    recipe.invoke(session, kind, operation, execute)
}

/// Targetless layout shared by direct relay and explicitly nested composition.
/// The enclosing operation still determines the native entry point; this helper
/// neither manufactures a target handle nor judges the nested protocol's policy.
pub(crate) fn with_relay_parameters<'a, T>(
    session: &Session,
    parameters: NativeSkipjackRelay<'a>,
    operation: ExtensionOperation,
    execute: impl FnOnce(ExtensionRequest<'_>, [Option<&'a NativeObjectRef>; 4]) -> Result<T>,
) -> Result<T> {
    encode_relay(parameters)?.invoke(session, CKM_SKIPJACK_RELAYX, operation, |request, keys| {
        execute(request, keys.references()?)
    })
}

pub(super) fn encode_relay(parameters: NativeSkipjackRelay<'_>) -> Result<Recipe<'_>> {
    let mut recipe = Recipe::new();
    recipe.length = size_of::<CK_SKIPJACK_RELAYX_PARAMS>();
    macro_rules! input {
        ($pointer:ident, $length:ident, $bytes:expr) => {
            recipe.input(
                offset_of!(CK_SKIPJACK_RELAYX_PARAMS, $pointer),
                offset_of!(CK_SKIPJACK_RELAYX_PARAMS, $length),
                Some($bytes),
            )?
        };
    }
    input!(pOldWrappedX, ulOldWrappedXLen, parameters.wrapped);
    input!(pOldPassword, ulOldPasswordLen, parameters.old_password);
    input!(
        pOldPublicData,
        ulOldPublicDataLen,
        parameters.old_public_data
    );
    input!(pOldRandomA, ulOldRandomLen, parameters.old_random);
    input!(pNewPassword, ulNewPasswordLen, parameters.new_password);
    input!(
        pNewPublicData,
        ulNewPublicDataLen,
        parameters.new_public_data
    );
    input!(pNewRandomA, ulNewRandomLen, parameters.new_random);
    Ok(recipe)
}

pub(super) fn encode<'a>(
    parameters: NativeTransportParameters<'a>,
    operation: ExtensionOperation,
) -> Result<(CK_MECHANISM_TYPE, Recipe<'a>)> {
    let mut r = Recipe::new();
    macro_rules! layout {
        ($t:ty) => {
            r.length = size_of::<$t>()
        };
    }
    macro_rules! set {
        ($t:ty, $f:ident, $v:expr) => {
            r.scalar(offset_of!($t, $f), $v)?
        };
    }
    macro_rules! input {
        ($t:ty, $p:ident, $l:ident, $b:expr) => {
            r.input(offset_of!($t, $p), offset_of!($t, $l), $b)?
        };
    }
    let ecdh_kind = match &parameters {
        NativeTransportParameters::EcdhAesCofactor { .. } => CKM_ECDH_COF_AES_KEY_WRAP,
        NativeTransportParameters::EcdhAesMontgomery { .. } => CKM_ECDH_X_AES_KEY_WRAP,
        _ => CKM_ECDH_AES_KEY_WRAP,
    };
    let kind = match parameters {
        NativeTransportParameters::Fixed { mechanism, bytes } => {
            if bytes.is_some_and(|b| b.len() != mechanism.bytes)
                || (bytes.is_none() && !mechanism.optional)
            {
                return Err(Error::Rejected(crate::RejectionReason::NativeTransport(
                    crate::NativeTransportRejection::TransportFixedParameterExtent,
                )));
            }
            r.raw_root = Some(bytes);
            mechanism.kind
        }
        NativeTransportParameters::RsaOaep(oaep) => {
            layout!(CK_RSA_PKCS_OAEP_PARAMS);
            r.oaep(oaep, false)?;
            CKM_RSA_PKCS_OAEP
        }
        NativeTransportParameters::RsaAes { aes_key_bits, oaep } => {
            layout!(CK_RSA_AES_KEY_WRAP_PARAMS);
            set!(CK_RSA_AES_KEY_WRAP_PARAMS, ulAESKeyBits, aes_key_bits);
            r.oaep(oaep, true)?;
            CKM_RSA_AES_KEY_WRAP
        }
        NativeTransportParameters::EcdhAes {
            aes_key_bits,
            kdf,
            shared,
        }
        | NativeTransportParameters::EcdhAesCofactor {
            aes_key_bits,
            kdf,
            shared,
        }
        | NativeTransportParameters::EcdhAesMontgomery {
            aes_key_bits,
            kdf,
            shared,
        } => {
            layout!(CK_ECDH_AES_KEY_WRAP_PARAMS);
            set!(CK_ECDH_AES_KEY_WRAP_PARAMS, ulAESKeyBits, aes_key_bits);
            set!(CK_ECDH_AES_KEY_WRAP_PARAMS, kdf, kdf);
            input!(
                CK_ECDH_AES_KEY_WRAP_PARAMS,
                pSharedData,
                ulSharedDataLen,
                shared
            );
            ecdh_kind
        }
        NativeTransportParameters::SetOaep {
            block_contents,
            extra,
        } => {
            layout!(CK_KEY_WRAP_SET_OAEP_PARAMS);
            r.root[offset_of!(CK_KEY_WRAP_SET_OAEP_PARAMS, bBC)] = block_contents;
            input!(CK_KEY_WRAP_SET_OAEP_PARAMS, pX, ulXLen, extra);
            CKM_KEY_WRAP_SET_OAEP
        }
        NativeTransportParameters::GostR3410 { oid, ukm, key } => {
            layout!(CK_GOSTR3410_KEY_WRAP_PARAMS);
            input!(CK_GOSTR3410_KEY_WRAP_PARAMS, pWrapOID, ulWrapOIDLen, oid);
            input!(CK_GOSTR3410_KEY_WRAP_PARAMS, pUKM, ulUKMLen, ukm);
            set!(
                CK_GOSTR3410_KEY_WRAP_PARAMS,
                hKey,
                key.identity.handle as u64
            );
            r.source = Some(ParameterKey::new(
                key,
                0,
                offset_of!(CK_GOSTR3410_KEY_WRAP_PARAMS, hKey),
            ));
            CKM_GOSTR3410_KEY_WRAP
        }
        NativeTransportParameters::AesCtr {
            counter_bits,
            counter_block,
        } => {
            layout!(CK_AES_CTR_PARAMS);
            set!(CK_AES_CTR_PARAMS, ulCounterBits, counter_bits);
            let offset = offset_of!(CK_AES_CTR_PARAMS, cb);
            r.root[offset..offset + counter_block.len()].copy_from_slice(&counter_block);
            CKM_AES_CTR
        }
        NativeTransportParameters::Stream(parameters) => {
            use crate::StreamCipherParameters::*;
            let (counter, nonce): (&[u8], &[u8]) = match parameters {
                ChaCha20 { counter, nonce } | Salsa20 { counter, nonce } => (counter, nonce),
                ChaCha20Ietf { counter, nonce } => (counter, nonce),
                XChaCha20 { counter, nonce } | XSalsa20 { counter, nonce } => (counter, nonce),
            };
            let kind = parameters.kind();
            if kind == CKM_CHACHA20 {
                layout!(CK_CHACHA20_PARAMS);
                r.pointer(
                    offset_of!(CK_CHACHA20_PARAMS, pBlockCounter),
                    Some(counter),
                    ExtensionDirection::Input,
                );
                set!(
                    CK_CHACHA20_PARAMS,
                    blockCounterBits,
                    (counter.len() * 8) as u64
                );
                r.pointer(
                    offset_of!(CK_CHACHA20_PARAMS, pNonce),
                    Some(nonce),
                    ExtensionDirection::Input,
                );
                set!(CK_CHACHA20_PARAMS, ulNonceBits, (nonce.len() * 8) as u64);
            } else {
                layout!(CK_SALSA20_PARAMS);
                r.pointer(
                    offset_of!(CK_SALSA20_PARAMS, pBlockCounter),
                    Some(counter),
                    ExtensionDirection::Input,
                );
                r.pointer(
                    offset_of!(CK_SALSA20_PARAMS, pNonce),
                    Some(nonce),
                    ExtensionDirection::Input,
                );
                set!(CK_SALSA20_PARAMS, ulNonceBits, (nonce.len() * 8) as u64);
            }
            kind
        }
        NativeTransportParameters::Rc(parameters) => {
            use crate::RcCipherParameters::*;
            let kind = parameters.kind();
            match parameters {
                Rc2Ecb { effective_bits } => {
                    r.length = size_of::<CK_ULONG>();
                    r.scalar(0, effective_bits)?;
                }
                Rc2Cbc { effective_bits, iv } | Rc2CbcPad { effective_bits, iv } => {
                    layout!(CK_RC2_CBC_PARAMS);
                    set!(CK_RC2_CBC_PARAMS, ulEffectiveBits, effective_bits);
                    let offset = offset_of!(CK_RC2_CBC_PARAMS, iv);
                    r.root[offset..offset + iv.len()].copy_from_slice(&iv);
                }
                Rc5Ecb { word_bytes, rounds } => {
                    layout!(CK_RC5_PARAMS);
                    set!(CK_RC5_PARAMS, ulWordsize, word_bytes);
                    set!(CK_RC5_PARAMS, ulRounds, rounds);
                }
                Rc5Cbc {
                    word_bytes,
                    rounds,
                    iv,
                }
                | Rc5CbcPad {
                    word_bytes,
                    rounds,
                    iv,
                } => {
                    layout!(CK_RC5_CBC_PARAMS);
                    set!(CK_RC5_CBC_PARAMS, ulWordsize, word_bytes);
                    set!(CK_RC5_CBC_PARAMS, ulRounds, rounds);
                    input!(CK_RC5_CBC_PARAMS, pIv, ulIvLen, Some(iv));
                }
            }
            kind
        }
        NativeTransportParameters::GcmWrap {
            iv,
            fixed_bits,
            generator,
            aad,
            tag_bits,
        } => {
            layout!(CK_GCM_WRAP_PARAMS);
            input!(CK_GCM_WRAP_PARAMS, pIv, ulIvLen, Some(iv));
            set!(CK_GCM_WRAP_PARAMS, ulIvFixedBits, fixed_bits);
            set!(CK_GCM_WRAP_PARAMS, ivGenerator, generator);
            input!(CK_GCM_WRAP_PARAMS, pAAD, ulAADLen, aad);
            set!(CK_GCM_WRAP_PARAMS, ulTagBits, tag_bits);
            if operation == ExtensionOperation::WrapKey && generator != CKG_NO_GENERATE as u64 {
                r.fields[0].2 = ExtensionDirection::InOut;
            }
            CKM_AES_GCM
        }
        NativeTransportParameters::CcmWrap {
            data_bytes,
            nonce,
            fixed_bits,
            generator,
            aad,
            mac_bytes,
        } => {
            layout!(CK_CCM_WRAP_PARAMS);
            set!(CK_CCM_WRAP_PARAMS, ulDataLen, data_bytes);
            input!(CK_CCM_WRAP_PARAMS, pNonce, ulNonceLen, Some(nonce));
            set!(CK_CCM_WRAP_PARAMS, ulNonceFixedBits, fixed_bits);
            set!(CK_CCM_WRAP_PARAMS, nonceGenerator, generator);
            input!(CK_CCM_WRAP_PARAMS, pAAD, ulAADLen, aad);
            set!(CK_CCM_WRAP_PARAMS, ulMACLen, mac_bytes);
            if operation == ExtensionOperation::WrapKey && generator != CKG_NO_GENERATE as u64 {
                r.fields[0].2 = ExtensionDirection::InOut;
            }
            CKM_AES_CCM
        }
        NativeTransportParameters::GcmClassic {
            contract,
            iv,
            iv_bits,
            aad,
            tag_bits,
        } => {
            r.assertion = Some(contract);
            layout!(CK_GCM_PARAMS);
            input!(CK_GCM_PARAMS, pIv, ulIvLen, Some(iv));
            set!(CK_GCM_PARAMS, ulIvBits, iv_bits);
            input!(CK_GCM_PARAMS, pAAD, ulAADLen, aad);
            set!(CK_GCM_PARAMS, ulTagBits, tag_bits);
            CKM_AES_GCM
        }
        NativeTransportParameters::GcmClassicWithoutIvBits {
            contract,
            iv,
            aad,
            tag_bits,
        } => {
            r.assertion = Some(contract);
            layout!(GcmWithoutIvBits);
            input!(GcmWithoutIvBits, pIv, ulIvLen, Some(iv));
            input!(GcmWithoutIvBits, pAAD, ulAADLen, aad);
            set!(GcmWithoutIvBits, ulTagBits, tag_bits);
            CKM_AES_GCM
        }
        NativeTransportParameters::CcmClassic {
            contract,
            data_bytes,
            nonce,
            aad,
            mac_bytes,
        } => {
            r.assertion = Some(contract);
            layout!(CK_CCM_PARAMS);
            set!(CK_CCM_PARAMS, ulDataLen, data_bytes);
            input!(CK_CCM_PARAMS, pNonce, ulNonceLen, Some(nonce));
            input!(CK_CCM_PARAMS, pAAD, ulAADLen, aad);
            set!(CK_CCM_PARAMS, ulMACLen, mac_bytes);
            CKM_AES_CCM
        }
        NativeTransportParameters::SkipjackPrivate(p) => {
            if p.prime.len() != p.base.len() {
                return Err(Error::Rejected(crate::RejectionReason::NativeTransport(
                    crate::NativeTransportRejection::SkipjackSharedPGExtent,
                )));
            }
            layout!(CK_SKIPJACK_PRIVATE_WRAP_PARAMS);
            input!(
                CK_SKIPJACK_PRIVATE_WRAP_PARAMS,
                pPassword,
                ulPasswordLen,
                Some(p.password)
            );
            input!(
                CK_SKIPJACK_PRIVATE_WRAP_PARAMS,
                pPublicData,
                ulPublicDataLen,
                Some(p.public_data)
            );
            input!(
                CK_SKIPJACK_PRIVATE_WRAP_PARAMS,
                pRandomA,
                ulRandomLen,
                Some(p.random)
            );
            input!(
                CK_SKIPJACK_PRIVATE_WRAP_PARAMS,
                pPrimeP,
                ulPAndGLen,
                Some(p.prime)
            );
            r.pointer(
                offset_of!(CK_SKIPJACK_PRIVATE_WRAP_PARAMS, pBaseG),
                Some(p.base),
                ExtensionDirection::Input,
            );
            input!(
                CK_SKIPJACK_PRIVATE_WRAP_PARAMS,
                pSubprimeQ,
                ulQLen,
                Some(p.subprime)
            );
            CKM_SKIPJACK_PRIVATE_WRAP
        }
    };
    Ok((kind, r))
}
