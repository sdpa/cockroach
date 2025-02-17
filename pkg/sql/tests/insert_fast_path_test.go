// Copyright 2022 The Cockroach Authors.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package tests

import (
	"context"
	gosql "database/sql"
	"testing"

	"github.com/cockroachdb/cockroach/pkg/base"
	"github.com/cockroachdb/cockroach/pkg/settings/cluster"
	"github.com/cockroachdb/cockroach/pkg/testutils/testcluster"
	"github.com/cockroachdb/cockroach/pkg/util/leaktest"
	"github.com/stretchr/testify/require"
)

// TestInsertFastPathExtendedProtocol verifies that the 1PC "insert fast path"
// optimization is applied when doing a simple INSERT with a prepared statement.
func TestInsertFastPathExtendedProtocol(t *testing.T) {
	defer leaktest.AfterTest(t)()
	ctx := context.Background()

	var db *gosql.DB

	params, _ := CreateTestServerParams()
	params.Settings = cluster.MakeTestingClusterSettings()

	tc := testcluster.StartTestCluster(t, 1, base.TestClusterArgs{ServerArgs: params})
	defer tc.Stopper().Stop(ctx)
	db = tc.ServerConn(0)
	_, err := db.Exec(`CREATE TABLE fast_path_test(val int);`)
	require.NoError(t, err)

	conn, err := db.Conn(ctx)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, "SET tracing = 'on'")
	require.NoError(t, err)
	// Use placeholders to force usage of extended protocol.
	_, err = conn.ExecContext(ctx, "INSERT INTO fast_path_test VALUES($1)", 1)
	require.NoError(t, err)

	fastPathEnabled := false
	rows, err := conn.QueryContext(ctx, "SELECT message, operation FROM [SHOW TRACE FOR SESSION]")
	require.NoError(t, err)
	for rows.Next() {
		var msg, operation string
		err = rows.Scan(&msg, &operation)
		require.NoError(t, err)
		if msg == "autocommit enabled" && operation == "batch flow coordinator" {
			fastPathEnabled = true
		}
	}
	require.NoError(t, rows.Err())
	require.True(t, fastPathEnabled)
	_, err = conn.ExecContext(ctx, "SET tracing = 'off'")
	require.NoError(t, err)
	err = conn.Close()
	require.NoError(t, err)

	// Verify that the insert committed successfully.
	var c int
	err = db.QueryRow("SELECT count(*) FROM fast_path_test").Scan(&c)
	require.NoError(t, err)
	require.Equal(t, 1, c, "expected 1 row, got %d", c)
}
