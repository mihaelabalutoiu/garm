// Code generated by go-swagger; DO NOT EDIT.

package enterprises

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	garm_params "github.com/cloudbase/garm/params"
)

// NewUpdateEnterprisePoolParams creates a new UpdateEnterprisePoolParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewUpdateEnterprisePoolParams() *UpdateEnterprisePoolParams {
	return &UpdateEnterprisePoolParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewUpdateEnterprisePoolParamsWithTimeout creates a new UpdateEnterprisePoolParams object
// with the ability to set a timeout on a request.
func NewUpdateEnterprisePoolParamsWithTimeout(timeout time.Duration) *UpdateEnterprisePoolParams {
	return &UpdateEnterprisePoolParams{
		timeout: timeout,
	}
}

// NewUpdateEnterprisePoolParamsWithContext creates a new UpdateEnterprisePoolParams object
// with the ability to set a context for a request.
func NewUpdateEnterprisePoolParamsWithContext(ctx context.Context) *UpdateEnterprisePoolParams {
	return &UpdateEnterprisePoolParams{
		Context: ctx,
	}
}

// NewUpdateEnterprisePoolParamsWithHTTPClient creates a new UpdateEnterprisePoolParams object
// with the ability to set a custom HTTPClient for a request.
func NewUpdateEnterprisePoolParamsWithHTTPClient(client *http.Client) *UpdateEnterprisePoolParams {
	return &UpdateEnterprisePoolParams{
		HTTPClient: client,
	}
}

/*
UpdateEnterprisePoolParams contains all the parameters to send to the API endpoint

	for the update enterprise pool operation.

	Typically these are written to a http.Request.
*/
type UpdateEnterprisePoolParams struct {

	/* Body.

	   Parameters used when updating the enterprise pool.
	*/
	Body garm_params.UpdatePoolParams

	/* EnterpriseID.

	   Enterprise ID.
	*/
	EnterpriseID string

	/* PoolID.

	   ID of the enterprise pool to update.
	*/
	PoolID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the update enterprise pool params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateEnterprisePoolParams) WithDefaults() *UpdateEnterprisePoolParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the update enterprise pool params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateEnterprisePoolParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the update enterprise pool params
func (o *UpdateEnterprisePoolParams) WithTimeout(timeout time.Duration) *UpdateEnterprisePoolParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update enterprise pool params
func (o *UpdateEnterprisePoolParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update enterprise pool params
func (o *UpdateEnterprisePoolParams) WithContext(ctx context.Context) *UpdateEnterprisePoolParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update enterprise pool params
func (o *UpdateEnterprisePoolParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update enterprise pool params
func (o *UpdateEnterprisePoolParams) WithHTTPClient(client *http.Client) *UpdateEnterprisePoolParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update enterprise pool params
func (o *UpdateEnterprisePoolParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the update enterprise pool params
func (o *UpdateEnterprisePoolParams) WithBody(body garm_params.UpdatePoolParams) *UpdateEnterprisePoolParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the update enterprise pool params
func (o *UpdateEnterprisePoolParams) SetBody(body garm_params.UpdatePoolParams) {
	o.Body = body
}

// WithEnterpriseID adds the enterpriseID to the update enterprise pool params
func (o *UpdateEnterprisePoolParams) WithEnterpriseID(enterpriseID string) *UpdateEnterprisePoolParams {
	o.SetEnterpriseID(enterpriseID)
	return o
}

// SetEnterpriseID adds the enterpriseId to the update enterprise pool params
func (o *UpdateEnterprisePoolParams) SetEnterpriseID(enterpriseID string) {
	o.EnterpriseID = enterpriseID
}

// WithPoolID adds the poolID to the update enterprise pool params
func (o *UpdateEnterprisePoolParams) WithPoolID(poolID string) *UpdateEnterprisePoolParams {
	o.SetPoolID(poolID)
	return o
}

// SetPoolID adds the poolId to the update enterprise pool params
func (o *UpdateEnterprisePoolParams) SetPoolID(poolID string) {
	o.PoolID = poolID
}

// WriteToRequest writes these params to a swagger request
func (o *UpdateEnterprisePoolParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if err := r.SetBodyParam(o.Body); err != nil {
		return err
	}

	// path param enterpriseID
	if err := r.SetPathParam("enterpriseID", o.EnterpriseID); err != nil {
		return err
	}

	// path param poolID
	if err := r.SetPathParam("poolID", o.PoolID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}