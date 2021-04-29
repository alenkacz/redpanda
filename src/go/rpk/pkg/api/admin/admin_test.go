// Copyright 2021 Vectorized, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

package admin

import (
	"encoding/json"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Shopify/sarama"
	"github.com/stretchr/testify/require"
)

func TestCreateUser(t *testing.T) {
	username := "Joss"
	password := "momorocks"
	algorithm := sarama.SASLTypeSCRAMSHA256
	body := newUser{
		User:      username,
		Password:  password,
		Algorithm: algorithm,
	}
	bs, err := json.Marshal(body)
	require.NoError(t, err)

	rand.Seed(time.Now().Unix())

	nNodes := rand.Int31n(6)
	urls := []string{}

	for i := 0; i < int(nNodes); i++ {
		n := i
		ts := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, err := ioutil.ReadAll(r.Body)
				require.NoError(t, err)
				require.Exactly(t, bs, b)
				// Have only one server return OK, to simulate a single
				// node being the leader and being able to respond.
				if n == 0 {
					w.WriteHeader(http.StatusOK)
				} else {
					w.WriteHeader(http.StatusInternalServerError)
				}
			}),
		)
		defer ts.Close()

		urls = append(urls, ts.URL)
	}

	adminClient, err := NewAdminAPI(urls, nil)
	require.NoError(t, err)
	err = adminClient.CreateUser(username, password)
	require.NoError(t, err)
}

func TestDeleteUser(t *testing.T) {
	username := "Lola"

	rand.Seed(time.Now().Unix())
	nNodes := rand.Int31n(6)
	urls := []string{}

	for i := 0; i < int(nNodes); i++ {
		n := i
		ts := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Exactly(t, "/v1/security/users/Lola", r.URL.Path)

				// Have only one server return OK, to simulate a single
				// node being the leader and being able to respond.
				if n == 0 {
					w.WriteHeader(http.StatusOK)
				} else {
					w.WriteHeader(http.StatusInternalServerError)
				}
			}),
		)
		defer ts.Close()

		urls = append(urls, ts.URL)
	}

	adminClient, err := NewAdminAPI(urls, nil)
	require.NoError(t, err)
	err = adminClient.DeleteUser(username)
	require.NoError(t, err)
}

func TestListUsers(t *testing.T) {
	rand.Seed(time.Now().Unix())
	nNodes := rand.Int31n(6)
	urls := []string{}

	for i := 0; i < int(nNodes); i++ {
		n := i
		ts := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if n == 0 {
					w.Write([]byte(
						`["Joss", "lola", "jeff", "tobias"]`,
					))
				} else {
					w.WriteHeader(http.StatusInternalServerError)
				}
			}),
		)
		defer ts.Close()

		urls = append(urls, ts.URL)
	}

	adminClient, err := NewAdminAPI(urls, nil)
	require.NoError(t, err)
	users, err := adminClient.ListUsers()
	require.NoError(t, err)
	require.Exactly(t, []string{"Joss", "lola", "jeff", "tobias"}, users)
}
