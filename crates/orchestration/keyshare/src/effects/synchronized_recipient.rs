// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use fhe_traits::DeserializeParametrized;

impl ThresholdKeyshare {
    pub(super) fn publish_synchronized_recipient_inputs(
        &self,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        if !self.effects_enabled
            || self.ended
            || self.canonical_key_published
            || self.params_profile.ensure_admission_enabled().is_err()
        {
            return Ok(());
        }
        let recovery = self.recovery.try_get()?;
        let Some(material) = &recovery.synchronized else {
            return Ok(());
        };
        let selected = recovery
            .ciphernode_selected
            .as_ref()
            .context("recipient intent has no selection")?;
        let config = e3_zk_config::synchronized::Configs::for_profile(
            self.params_profile,
            self.state.try_get()?.committee_size()?,
        )?;
        let key = self
            .bfv_key
            .as_ref()
            .context("recipient intent has no durable transport key")?;
        let public_key = fhe::bfv::PublicKey::from_bytes(&key.pk_bfv, &config.transport)?;
        let input = material.recipient_inputs(
            selected,
            self.interfold_address,
            &public_key,
            &self.cipher,
        )?;
        self.bus.publish(input, ec)?;
        Ok(())
    }
}
