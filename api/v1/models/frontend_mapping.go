// Code generated by go-swagger; DO NOT EDIT.

// Copyright Authors of Cilium
// SPDX-License-Identifier: Apache-2.0

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// FrontendMapping Mapping of frontend to backend pods of an LRP
//
// swagger:model FrontendMapping
type FrontendMapping struct {

	// Pod backends of an LRP
	Backends []*LRPBackend `json:"backends"`

	// frontend address
	FrontendAddress *FrontendAddress `json:"frontend-address,omitempty"`
}

// Validate validates this frontend mapping
func (m *FrontendMapping) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateBackends(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFrontendAddress(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *FrontendMapping) validateBackends(formats strfmt.Registry) error {
	if swag.IsZero(m.Backends) { // not required
		return nil
	}

	for i := 0; i < len(m.Backends); i++ {
		if swag.IsZero(m.Backends[i]) { // not required
			continue
		}

		if m.Backends[i] != nil {
			if err := m.Backends[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("backends" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("backends" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *FrontendMapping) validateFrontendAddress(formats strfmt.Registry) error {
	if swag.IsZero(m.FrontendAddress) { // not required
		return nil
	}

	if m.FrontendAddress != nil {
		if err := m.FrontendAddress.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("frontend-address")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("frontend-address")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this frontend mapping based on the context it is used
func (m *FrontendMapping) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateBackends(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateFrontendAddress(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *FrontendMapping) contextValidateBackends(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Backends); i++ {

		if m.Backends[i] != nil {

			if swag.IsZero(m.Backends[i]) { // not required
				return nil
			}

			if err := m.Backends[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("backends" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("backends" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *FrontendMapping) contextValidateFrontendAddress(ctx context.Context, formats strfmt.Registry) error {

	if m.FrontendAddress != nil {

		if swag.IsZero(m.FrontendAddress) { // not required
			return nil
		}

		if err := m.FrontendAddress.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("frontend-address")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("frontend-address")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *FrontendMapping) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *FrontendMapping) UnmarshalBinary(b []byte) error {
	var res FrontendMapping
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
