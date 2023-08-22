// Code generated by go-swagger; DO NOT EDIT.

package repositories

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	apiserver_params "github.com/cloudbase/garm/apiserver/params"
)

// UninstallRepoWebhookReader is a Reader for the UninstallRepoWebhook structure.
type UninstallRepoWebhookReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UninstallRepoWebhookReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	result := NewUninstallRepoWebhookDefault(response.Code())
	if err := result.readResponse(response, consumer, o.formats); err != nil {
		return nil, err
	}
	if response.Code()/100 == 2 {
		return result, nil
	}
	return nil, result
}

// NewUninstallRepoWebhookDefault creates a UninstallRepoWebhookDefault with default headers values
func NewUninstallRepoWebhookDefault(code int) *UninstallRepoWebhookDefault {
	return &UninstallRepoWebhookDefault{
		_statusCode: code,
	}
}

/*
UninstallRepoWebhookDefault describes a response with status code -1, with default header values.

APIErrorResponse
*/
type UninstallRepoWebhookDefault struct {
	_statusCode int

	Payload apiserver_params.APIErrorResponse
}

// IsSuccess returns true when this uninstall repo webhook default response has a 2xx status code
func (o *UninstallRepoWebhookDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this uninstall repo webhook default response has a 3xx status code
func (o *UninstallRepoWebhookDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this uninstall repo webhook default response has a 4xx status code
func (o *UninstallRepoWebhookDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this uninstall repo webhook default response has a 5xx status code
func (o *UninstallRepoWebhookDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this uninstall repo webhook default response a status code equal to that given
func (o *UninstallRepoWebhookDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the uninstall repo webhook default response
func (o *UninstallRepoWebhookDefault) Code() int {
	return o._statusCode
}

func (o *UninstallRepoWebhookDefault) Error() string {
	return fmt.Sprintf("[DELETE /repositories/{repoID}/webhook][%d] UninstallRepoWebhook default  %+v", o._statusCode, o.Payload)
}

func (o *UninstallRepoWebhookDefault) String() string {
	return fmt.Sprintf("[DELETE /repositories/{repoID}/webhook][%d] UninstallRepoWebhook default  %+v", o._statusCode, o.Payload)
}

func (o *UninstallRepoWebhookDefault) GetPayload() apiserver_params.APIErrorResponse {
	return o.Payload
}

func (o *UninstallRepoWebhookDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}