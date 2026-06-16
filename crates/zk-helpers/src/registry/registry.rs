// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::computation::DkgInputType;
use e3_fhe_params::ParameterType;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

/// Errors produced by the circuit registry.
#[derive(Error, Debug)]
pub enum RegistryError {
    #[error("Unknown circuit: {name}")]
    UnknownCircuit { name: String },
}

/// Trait for circuit metadata.
pub trait Circuit: Send + Sync {
    const NAME: &'static str;
    const PREFIX: &'static str;
    const SUPPORTED_PARAMETER: ParameterType;
    const DKG_INPUT_TYPE: Option<DkgInputType>;

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn prefix(&self) -> &'static str {
        Self::PREFIX
    }

    fn supported_parameter(&self) -> ParameterType {
        Self::SUPPORTED_PARAMETER
    }

    fn dkg_input_type(&self) -> Option<DkgInputType> {
        Self::DKG_INPUT_TYPE
    }
}

pub trait CircuitMetadata: Send + Sync {
    fn name(&self) -> &'static str;
    fn supported_parameter(&self) -> ParameterType;
    fn dkg_input_type(&self) -> Option<DkgInputType>;
}

impl<T: Circuit> CircuitMetadata for T {
    fn name(&self) -> &'static str {
        T::NAME
    }

    fn supported_parameter(&self) -> ParameterType {
        T::SUPPORTED_PARAMETER
    }

    fn dkg_input_type(&self) -> Option<DkgInputType> {
        T::DKG_INPUT_TYPE
    }
}

/// Registry for ZK circuits.
pub struct CircuitRegistry {
    circuits: HashMap<String, Arc<dyn CircuitMetadata>>,
}

impl Default for CircuitRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl CircuitRegistry {
    /// Build an empty registry.
    pub fn new() -> Self {
        Self {
            circuits: HashMap::new(),
        }
    }

    /// Register a circuit descriptor under a name.
    pub fn register(&mut self, circuit: Arc<dyn CircuitMetadata>) {
        self.circuits.insert(circuit.name().to_lowercase(), circuit);
    }

    /// Get a circuit descriptor from the registry.
    pub fn get(&self, name: &str) -> Result<Arc<dyn CircuitMetadata>, RegistryError> {
        self.circuits
            .get(&name.to_lowercase())
            .cloned()
            .ok_or_else(|| RegistryError::UnknownCircuit {
                name: name.to_string(),
            })
    }

    /// Return supported parameter types for a circuit.
    pub fn supported_parameter_type(&self, name: &str) -> Result<ParameterType, RegistryError> {
        Ok(self.get(name)?.supported_parameter())
    }

    /// Return DKG input type for a circuit, if any.
    pub fn dkg_input_type(&self, name: &str) -> Result<Option<DkgInputType>, RegistryError> {
        Ok(self.get(name)?.dkg_input_type())
    }

    /// List all registered circuit names.
    pub fn list_circuits(&self) -> Vec<String> {
        self.circuits.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub struct TestCircuit;

    impl Circuit for TestCircuit {
        const NAME: &'static str = "test";
        const PREFIX: &'static str = "TEST";
        const SUPPORTED_PARAMETER: ParameterType = ParameterType::DKG;
        const DKG_INPUT_TYPE: Option<DkgInputType> = Some(DkgInputType::SecretKey);
    }

    #[test]
    /// Unknown circuits should return an error.
    fn registry_rejects_unknown_circuit() {
        let registry = CircuitRegistry::new();
        assert!(matches!(
            registry.get("unknown"),
            Err(RegistryError::UnknownCircuit { .. })
        ));
    }

    #[test]
    /// Registry should expose metadata for registered circuits.
    fn registry_reports_expected_metadata() {
        let mut registry = CircuitRegistry::new();
        registry.register(Arc::new(TestCircuit));
        let circuit = registry.get(<TestCircuit as Circuit>::NAME).unwrap();

        assert_eq!(circuit.name(), <TestCircuit as Circuit>::NAME);
        assert_eq!(circuit.supported_parameter(), ParameterType::DKG);
        assert!(circuit.dkg_input_type().is_some());
    }
}
