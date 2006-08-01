/**
 * Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * DRI: Cyrus Daboo, cdaboo@apple.com
 **/

#include <Python/Python.h>

#include "kerberosbasic.h"
#include "kerberosgss.h"

static PyObject *checkPassword(PyObject *self, PyObject *args)
{
    const char *user;
    const char *pswd;
    const char *service;
    const char *default_realm;
    int result = 0;
	
    if (!PyArg_ParseTuple(args, "ssss", &user, &pswd, &service, &default_realm))
        return NULL;
	
	result = authenticate_user_krb5pwd(user, pswd, service, default_realm);
	
	if (result)
		return Py_INCREF(Py_True), Py_True;
	else
		return Py_INCREF(Py_False), Py_False;
}

static PyObject *authGSSClientInit(PyObject *self, PyObject *args)
{
    const char *service;
    gss_client_state *state;
	PyObject *pystate;
    int result = 0;
	
    if (!PyArg_ParseTuple(args, "s", &service))
        return NULL;
	
	state = (gss_client_state *) malloc(sizeof(gss_client_state));
	pystate = PyCObject_FromVoidPtr(state, NULL);
	
	result = authenticate_gss_client_init(service, state);
	
    return Py_BuildValue("(iO)", result, pystate);
}

static PyObject *authGSSClientClean(PyObject *self, PyObject *args)
{
    gss_client_state *state;
	PyObject *pystate;
    int result = 0;
	
    if (!PyArg_ParseTuple(args, "O", &pystate) || !PyCObject_Check(pystate))
        return NULL;
	
	state = (gss_client_state *)PyCObject_AsVoidPtr(pystate);
	if (state != NULL)
	{
		result = authenticate_gss_client_clean(state);
		
		free(state);
		PyCObject_SetVoidPtr(pystate, NULL);
	}
	
    return Py_BuildValue("i", result);
}

static PyObject *authGSSClientStep(PyObject *self, PyObject *args)
{
    gss_client_state *state;
	PyObject *pystate;
	char *challenge;
    int result = 0;
	
    if (!PyArg_ParseTuple(args, "Os", &pystate, &challenge) || !PyCObject_Check(pystate))
        return NULL;
	
	state = (gss_client_state *)PyCObject_AsVoidPtr(pystate);
	if (state == NULL)
		return NULL;

	result = authenticate_gss_client_step(state, challenge);
	
    return Py_BuildValue("i", result);
}

static PyObject *authGSSClientResponse(PyObject *self, PyObject *args)
{
    gss_client_state *state;
	PyObject *pystate;
	
    if (!PyArg_ParseTuple(args, "O", &pystate) || !PyCObject_Check(pystate))
        return NULL;
	
	state = (gss_client_state *)PyCObject_AsVoidPtr(pystate);
	if (state == NULL)
		return NULL;
	
    return Py_BuildValue("s", state->response);
}

static PyObject *authGSSClientUserName(PyObject *self, PyObject *args)
{
    gss_client_state *state;
	PyObject *pystate;
	
    if (!PyArg_ParseTuple(args, "O", &pystate) || !PyCObject_Check(pystate))
        return NULL;
	
	state = (gss_client_state *)PyCObject_AsVoidPtr(pystate);
	if (state == NULL)
		return NULL;
	
    return Py_BuildValue("s", state->username);
}

static PyObject *authGSSServerInit(PyObject *self, PyObject *args)
{
    const char *service;
    gss_server_state *state;
	PyObject *pystate;
    int result = 0;
	
    if (!PyArg_ParseTuple(args, "s", &service))
        return NULL;
	
	state = (gss_server_state *) malloc(sizeof(gss_server_state));
	pystate = PyCObject_FromVoidPtr(state, NULL);
	
	result = authenticate_gss_server_init(service, state);
	
    return Py_BuildValue("(iO)", result, pystate);
}

static PyObject *authGSSServerClean(PyObject *self, PyObject *args)
{
    gss_server_state *state;
	PyObject *pystate;
    int result = 0;
	
    if (!PyArg_ParseTuple(args, "O", &pystate) || !PyCObject_Check(pystate))
        return NULL;
	
	state = (gss_server_state *)PyCObject_AsVoidPtr(pystate);
	if (state != NULL)
	{
		result = authenticate_gss_server_clean(state);
		
		free(state);
		PyCObject_SetVoidPtr(pystate, NULL);
	}
	
    return Py_BuildValue("i", result);
}

static PyObject *authGSSServerStep(PyObject *self, PyObject *args)
{
    gss_server_state *state;
	PyObject *pystate;
	char *challenge;
    int result = 0;
	
    if (!PyArg_ParseTuple(args, "Os", &pystate, &challenge) || !PyCObject_Check(pystate))
        return NULL;
	
	state = (gss_server_state *)PyCObject_AsVoidPtr(pystate);
	if (state == NULL)
		return NULL;
	
	result = authenticate_gss_server_step(state, challenge);
	
    return Py_BuildValue("i", result);
}

static PyObject *authGSSServerResponse(PyObject *self, PyObject *args)
{
    gss_server_state *state;
	PyObject *pystate;
	
    if (!PyArg_ParseTuple(args, "O", &pystate) || !PyCObject_Check(pystate))
        return NULL;
	
	state = (gss_server_state *)PyCObject_AsVoidPtr(pystate);
	if (state == NULL)
		return NULL;
	
    return Py_BuildValue("s", state->response);
}

static PyObject *authGSSServerUserName(PyObject *self, PyObject *args)
{
    gss_server_state *state;
	PyObject *pystate;
	
    if (!PyArg_ParseTuple(args, "O", &pystate) || !PyCObject_Check(pystate))
        return NULL;
	
	state = (gss_server_state *)PyCObject_AsVoidPtr(pystate);
	if (state == NULL)
		return NULL;
	
    return Py_BuildValue("s", state->username);
}

static PyMethodDef SpamMethods[] = {
    {"checkPassword",  checkPassword, METH_VARARGS,
		"Check the supplied user/password against Kerberos KDC."},
    {"authGSSClientInit",  authGSSClientInit, METH_VARARGS,
		"Initialize client-side GSSAPI operations."},
    {"authGSSClientClean",  authGSSClientClean, METH_VARARGS,
		"Terminate client-side GSSAPI operations."},
    {"authGSSClientStep",  authGSSClientStep, METH_VARARGS,
		"Do a client-side GSSAPI step."},
    {"authGSSClientResponse",  authGSSClientResponse, METH_VARARGS,
		"Get the response from the last client-side GSSAPI step."},
    {"authGSSClientUserName",  authGSSClientUserName, METH_VARARGS,
		"Get the user name from the last client-side GSSAPI step."},
    {"authGSSServerInit",  authGSSServerInit, METH_VARARGS,
		"Initialize server-side GSSAPI operations."},
    {"authGSSServerClean",  authGSSServerClean, METH_VARARGS,
		"Terminate server-side GSSAPI operations."},
    {"authGSSServerStep",  authGSSServerStep, METH_VARARGS,
		"Do a server-side GSSAPI step."},
    {"authGSSServerResponse",  authGSSServerResponse, METH_VARARGS,
		"Get the response from the last server-side GSSAPI step."},
    {"authGSSServerUserName",  authGSSServerUserName, METH_VARARGS,
		"Get the user name from the last server-side GSSAPI step."},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyMODINIT_FUNC initkerberos(void)
{
    (void) Py_InitModule("kerberos", SpamMethods);
}
