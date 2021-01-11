// Code generated by go-swagger; DO NOT EDIT.

// Copyright 2017-2021 Authors of Cilium
// SPDX-License-Identifier: Apache-2.0

package service

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/cilium/cilium/api/v1/models"
)

// DeleteServiceIDOKCode is the HTTP code returned for type DeleteServiceIDOK
const DeleteServiceIDOKCode int = 200

/*DeleteServiceIDOK Success

swagger:response deleteServiceIdOK
*/
type DeleteServiceIDOK struct {
}

// NewDeleteServiceIDOK creates DeleteServiceIDOK with default headers values
func NewDeleteServiceIDOK() *DeleteServiceIDOK {

	return &DeleteServiceIDOK{}
}

// WriteResponse to the client
func (o *DeleteServiceIDOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.Header().Del(runtime.HeaderContentType) //Remove Content-Type on empty responses

	rw.WriteHeader(200)
}

// DeleteServiceIDNotFoundCode is the HTTP code returned for type DeleteServiceIDNotFound
const DeleteServiceIDNotFoundCode int = 404

/*DeleteServiceIDNotFound Service not found

swagger:response deleteServiceIdNotFound
*/
type DeleteServiceIDNotFound struct {
}

// NewDeleteServiceIDNotFound creates DeleteServiceIDNotFound with default headers values
func NewDeleteServiceIDNotFound() *DeleteServiceIDNotFound {

	return &DeleteServiceIDNotFound{}
}

// WriteResponse to the client
func (o *DeleteServiceIDNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.Header().Del(runtime.HeaderContentType) //Remove Content-Type on empty responses

	rw.WriteHeader(404)
}

// DeleteServiceIDFailureCode is the HTTP code returned for type DeleteServiceIDFailure
const DeleteServiceIDFailureCode int = 500

/*DeleteServiceIDFailure Service deletion failed

swagger:response deleteServiceIdFailure
*/
type DeleteServiceIDFailure struct {

	/*
	  In: Body
	*/
	Payload models.Error `json:"body,omitempty"`
}

// NewDeleteServiceIDFailure creates DeleteServiceIDFailure with default headers values
func NewDeleteServiceIDFailure() *DeleteServiceIDFailure {

	return &DeleteServiceIDFailure{}
}

// WithPayload adds the payload to the delete service Id failure response
func (o *DeleteServiceIDFailure) WithPayload(payload models.Error) *DeleteServiceIDFailure {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete service Id failure response
func (o *DeleteServiceIDFailure) SetPayload(payload models.Error) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteServiceIDFailure) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(500)
	payload := o.Payload
	if err := producer.Produce(rw, payload); err != nil {
		panic(err) // let the recovery middleware deal with this
	}
}
