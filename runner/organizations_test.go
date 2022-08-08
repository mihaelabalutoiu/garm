// Copyright 2022 Cloudbase Solutions SRL
//
//    Licensed under the Apache License, Version 2.0 (the "License"); you may
//    not use this file except in compliance with the License. You may obtain
//    a copy of the License at
//
//         http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
//    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
//    License for the specific language governing permissions and limitations
//    under the License.

package runner

import (
	"context"
	"fmt"
	"garm/auth"
	"garm/config"
	"garm/database"
	dbCommon "garm/database/common"
	runnerErrors "garm/errors"
	"garm/params"
	"garm/runner/common"
	runnerCommonMocks "garm/runner/common/mocks"
	runnerMocks "garm/runner/mocks"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

var (
	EncryptionPassphrase = "bocyasicgatEtenOubwonIbsudNutDom"
)

type OrgTestFixtures struct {
	AdminContext          context.Context
	DBFile                string
	Store                 dbCommon.Store
	StoreOrgs             map[string]params.Organization
	Providers             map[string]common.Provider
	Credentials           map[string]config.Github
	CreateOrgParams       params.CreateOrgParams
	CreatePoolParams      params.CreatePoolParams
	UpdateRepoParams      params.UpdateRepositoryParams
	UpdatePoolStateParams params.UpdatePoolStateParams
	ErrMock               error
	ProviderMock          *runnerCommonMocks.Provider
	PoolMgrMock           *runnerCommonMocks.PoolManager
	PoolMgrCtrlMock       *runnerMocks.PoolManagerController
}

type OrgTestSuite struct {
	suite.Suite
	Fixtures *OrgTestFixtures
	Runner   *Runner
}

func getTestSqliteDBConfig(t *testing.T) config.Database {
	dir, err := os.MkdirTemp("", "garm-config-test")
	if err != nil {
		t.Fatalf("failed to create temporary directory: %s", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	return config.Database{
		Debug:      false,
		DbBackend:  config.SQLiteBackend,
		Passphrase: EncryptionPassphrase,
		SQLite: config.SQLite{
			DBFile: filepath.Join(dir, "garm.db"),
		},
	}
}

func (s *OrgTestSuite) SetupTest() {
	adminCtx := auth.GetAdminContext()

	// create testing sqlite database
	dbCfg := getTestSqliteDBConfig(s.T())
	db, err := database.NewDatabase(adminCtx, dbCfg)
	if err != nil {
		s.Fail("failed to create db connection: %s", err)
	}

	// create some organization objects in the database, for testing purposes
	orgs := map[string]params.Organization{}
	for i := 1; i <= 3; i++ {
		name := fmt.Sprintf("test-org-%v", i)
		org, err := db.CreateOrganization(
			adminCtx,
			name,
			fmt.Sprintf("test-creds-%v", i),
			fmt.Sprintf("test-webhook-secret-%v", i),
		)
		if err != nil {
			s.Fail("failed to create database object (test-org-%v)", i)
		}
		orgs[name] = org
	}

	// setup test fixtures
	providerMock := runnerCommonMocks.NewProvider(s.T())
	fixtures := &OrgTestFixtures{
		AdminContext: adminCtx,
		DBFile:       dbCfg.SQLite.DBFile,
		Store:        db,
		StoreOrgs:    orgs,
		Providers: map[string]common.Provider{
			"test-provider": providerMock,
		},
		Credentials: map[string]config.Github{
			"test-creds": {
				Name:        "test-creds-name",
				Description: "test-creds-description",
				OAuth2Token: "test-creds-oauth2-token",
			},
		},
		CreateOrgParams: params.CreateOrgParams{
			Name:            "test-org-create",
			CredentialsName: "test-creds",
		},
		CreatePoolParams: params.CreatePoolParams{
			ProviderName:           "test-provider",
			MaxRunners:             4,
			MinIdleRunners:         2,
			Image:                  "test",
			Flavor:                 "test",
			OSType:                 "linux",
			OSArch:                 "arm64",
			Tags:                   []string{"self-hosted", "arm64", "linux"},
			RunnerBootstrapTimeout: 0,
		},
		UpdateRepoParams: params.UpdateRepositoryParams{
			CredentialsName: "test-creds",
			WebhookSecret:   "test-update-repo-webhook-secret",
		},
		UpdatePoolStateParams: params.UpdatePoolStateParams{
			WebhookSecret: "test-update-repo-webhook-secret",
		},
		ErrMock:         fmt.Errorf("mock error"),
		ProviderMock:    providerMock,
		PoolMgrMock:     runnerCommonMocks.NewPoolManager(s.T()),
		PoolMgrCtrlMock: runnerMocks.NewPoolManagerController(s.T()),
	}
	s.Fixtures = fixtures

	// setup test runner
	runner := &Runner{
		providers:       fixtures.Providers,
		credentials:     fixtures.Credentials,
		ctx:             fixtures.AdminContext,
		store:           fixtures.Store,
		poolManagerCtrl: fixtures.PoolMgrCtrlMock,
	}
	s.Runner = runner
}

func (s *OrgTestSuite) TestCreateOrganization() {
	// setup mocks expectations
	s.Fixtures.PoolMgrMock.On("Start").Return(nil)
	s.Fixtures.PoolMgrCtrlMock.On("CreateOrgPoolManager", s.Fixtures.AdminContext, mock.AnythingOfType("params.Organization"), s.Fixtures.Providers, s.Fixtures.Store).Return(s.Fixtures.PoolMgrMock, nil)

	// call tested function
	org, err := s.Runner.CreateOrganization(s.Fixtures.AdminContext, s.Fixtures.CreateOrgParams)

	// assertions
	s.Fixtures.PoolMgrMock.AssertExpectations(s.T())
	s.Fixtures.PoolMgrCtrlMock.AssertExpectations(s.T())
	s.Require().Nil(err)
	s.Require().Equal(s.Fixtures.CreateOrgParams.Name, org.Name)
	s.Require().Equal(s.Fixtures.Credentials[s.Fixtures.CreateOrgParams.CredentialsName].Name, org.CredentialsName)
}

func (s *OrgTestSuite) TestCreateOrganizationErrUnauthorized() {
	_, err := s.Runner.CreateOrganization(context.Background(), s.Fixtures.CreateOrgParams)

	s.Require().Equal(runnerErrors.ErrUnauthorized, err)
}

func (s *OrgTestSuite) TestCreateOrganizationEmptyParams() {
	_, err := s.Runner.CreateOrganization(s.Fixtures.AdminContext, params.CreateOrgParams{})

	s.Require().Regexp("validating params: missing org name", err.Error())
}

func (s *OrgTestSuite) TestCreateOrganizationMissingCredentials() {
	s.Fixtures.CreateOrgParams.CredentialsName = "not-existent-creds-name"

	_, err := s.Runner.CreateOrganization(s.Fixtures.AdminContext, s.Fixtures.CreateOrgParams)

	s.Require().Equal(runnerErrors.NewBadRequestError("credentials %s not defined", s.Fixtures.CreateOrgParams.CredentialsName), err)
}

func (s *OrgTestSuite) TestCreateOrganizationOrgFetchFailed() {
	// corrupt database file to make sure that `r.store.GetOrganization` fails unexpected.
	if err := os.WriteFile(s.Fixtures.DBFile, []byte("corrupted content"), os.ModeAppend); err != nil {
		s.Fail("cannot write to DB file: %s", s.Fixtures.DBFile)
	}

	_, err := s.Runner.CreateOrganization(s.Fixtures.AdminContext, s.Fixtures.CreateOrgParams)

	s.Require().Regexp("fetching org", err.Error())
}

func (s *OrgTestSuite) TestCreateOrganizationAlreadyExists() {
	s.Fixtures.CreateOrgParams.Name = "test-org-1" // this is already created in `SetupTest()`

	_, err := s.Runner.CreateOrganization(s.Fixtures.AdminContext, s.Fixtures.CreateOrgParams)

	s.Require().Equal(runnerErrors.NewConflictError("organization %s already exists", s.Fixtures.CreateOrgParams.Name), err)
}

func (s *OrgTestSuite) TestCreateOrganizationPoolMgrFailed() {
	s.Fixtures.PoolMgrCtrlMock.On("CreateOrgPoolManager", s.Fixtures.AdminContext, mock.AnythingOfType("params.Organization"), s.Fixtures.Providers, s.Fixtures.Store).Return(s.Fixtures.PoolMgrMock, s.Fixtures.ErrMock)

	_, err := s.Runner.CreateOrganization(s.Fixtures.AdminContext, s.Fixtures.CreateOrgParams)

	s.Fixtures.PoolMgrMock.AssertExpectations(s.T())
	s.Fixtures.PoolMgrCtrlMock.AssertExpectations(s.T())
	s.Require().Equal(fmt.Sprintf("creating org pool manager: %s", s.Fixtures.ErrMock.Error()), err.Error())
}

func (s *OrgTestSuite) TestCreateOrganizationStartPoolMgrFailed() {
	s.Fixtures.PoolMgrMock.On("Start").Return(s.Fixtures.ErrMock)
	s.Fixtures.PoolMgrCtrlMock.On("CreateOrgPoolManager", s.Fixtures.AdminContext, mock.AnythingOfType("params.Organization"), s.Fixtures.Providers, s.Fixtures.Store).Return(s.Fixtures.PoolMgrMock, nil)
	s.Fixtures.PoolMgrCtrlMock.On("DeleteOrgPoolManager", mock.AnythingOfType("params.Organization")).Return(s.Fixtures.ErrMock)

	_, err := s.Runner.CreateOrganization(s.Fixtures.AdminContext, s.Fixtures.CreateOrgParams)

	s.Fixtures.PoolMgrMock.AssertExpectations(s.T())
	s.Fixtures.PoolMgrCtrlMock.AssertExpectations(s.T())
	s.Require().Equal(fmt.Sprintf("starting org pool manager: %s", s.Fixtures.ErrMock.Error()), err.Error())
}

func (s *OrgTestSuite) TestListOrganizations() {
	orgs, err := s.Runner.ListOrganizations(s.Fixtures.AdminContext)

	s.Require().Nil(err)
	s.Require().Equal(len(orgs), len(s.Fixtures.StoreOrgs))
}

func (s *OrgTestSuite) TestListOrganizationsErrUnauthorized() {
	_, err := s.Runner.ListOrganizations(context.Background())

	s.Require().Equal(runnerErrors.ErrUnauthorized, err)
}

func (s *OrgTestSuite) TestListOrganizationsFailed() {
	// corrupt database file to make sure that `r.store.ListOrganizations` fails unexpected.
	if err := os.WriteFile(s.Fixtures.DBFile, []byte("corrupted content"), os.ModeAppend); err != nil {
		s.Fail("cannot write to DB file: %s", s.Fixtures.DBFile)
	}
	_, err := s.Runner.ListOrganizations(s.Fixtures.AdminContext)

	s.Require().Regexp("listing organizations", err.Error())
}

func (s *OrgTestSuite) TestGetOrganizationByID() {
	org, err := s.Runner.GetOrganizationByID(s.Fixtures.AdminContext, s.Fixtures.StoreOrgs["test-org-1"].ID)

	s.Require().Nil(err)
	s.Require().Equal(s.Fixtures.StoreOrgs["test-org-1"].ID, org.ID)
}

func (s *OrgTestSuite) TestGetOrganizationByIDErrUnauthorized() {
	_, err := s.Runner.GetOrganizationByID(context.Background(), "org-id")

	s.Require().Equal(runnerErrors.ErrUnauthorized, err)
}

func (s *OrgTestSuite) TestGetOrganizationByIDFetchFailed() {
	// corrupt database file to make sure that `r.store.GetOrganizationByID` fails unexpected.
	if err := os.WriteFile(s.Fixtures.DBFile, []byte("corrupted content"), os.ModeAppend); err != nil {
		s.Fail("cannot write to DB file: %s", s.Fixtures.DBFile)
	}
	_, err := s.Runner.GetOrganizationByID(s.Fixtures.AdminContext, "org-id")

	s.Require().Regexp("fetching organization", err.Error())
}

func (s *OrgTestSuite) TestDeleteOrganization() {
	s.Fixtures.PoolMgrCtrlMock.On("DeleteOrgPoolManager", mock.AnythingOfType("params.Organization")).Return(nil)

	err := s.Runner.DeleteOrganization(s.Fixtures.AdminContext, s.Fixtures.StoreOrgs["test-org-3"].ID)

	s.Fixtures.PoolMgrCtrlMock.AssertExpectations(s.T())
	s.Require().Nil(err)
	orgs, err := s.Fixtures.Store.ListOrganizations(s.Fixtures.AdminContext)
	if err != nil {
		s.Fail("cannot list store organizations: %v", err)
	}
	s.Require().Equal(len(s.Fixtures.StoreOrgs)-1, len(orgs))
}

func (s *OrgTestSuite) TestDeleteOrganizationErrUnauthorized() {
	err := s.Runner.DeleteOrganization(context.Background(), "org-id")

	s.Require().Equal(runnerErrors.ErrUnauthorized, err)
}

func (s *OrgTestSuite) TestDeleteOrganizationFetchOrgFailed() {
	// corrupt database file to make sure that `r.store.GetOrganizationByID` fails unexpected.
	if err := os.WriteFile(s.Fixtures.DBFile, []byte("corrupted content"), os.ModeAppend); err != nil {
		s.Fail("cannot write to DB file: %s", s.Fixtures.DBFile)
	}

	err := s.Runner.DeleteOrganization(s.Fixtures.AdminContext, "org-id")

	s.Require().Regexp("fetching org:", err.Error())
}

func (s *OrgTestSuite) TestDeleteOrganizationPoolDefinedFailed() {
	pool, err := s.Fixtures.Store.CreateOrganizationPool(s.Fixtures.AdminContext, s.Fixtures.StoreOrgs["test-org-1"].ID, s.Fixtures.CreatePoolParams)
	if err != nil {
		s.Fail("cannot create store organizations pool: %v", err)
	}

	err = s.Runner.DeleteOrganization(s.Fixtures.AdminContext, s.Fixtures.StoreOrgs["test-org-1"].ID)

	s.Require().Equal(runnerErrors.NewBadRequestError("org has pools defined (%s)", pool.ID), err)
}

func (s *OrgTestSuite) TestDeleteOrganizationPoolMgrFailed() {
	s.Fixtures.PoolMgrCtrlMock.On("DeleteOrgPoolManager", mock.AnythingOfType("params.Organization")).Return(s.Fixtures.ErrMock)

	err := s.Runner.DeleteOrganization(s.Fixtures.AdminContext, s.Fixtures.StoreOrgs["test-org-1"].ID)

	s.Fixtures.PoolMgrCtrlMock.AssertExpectations(s.T())
	s.Require().Equal(fmt.Sprintf("deleting org pool manager: %s", s.Fixtures.ErrMock.Error()), err.Error())
}

func (s *OrgTestSuite) TestUpdateOrganization() {
	s.Fixtures.PoolMgrCtrlMock.On("GetOrgPoolManager", mock.AnythingOfType("params.Organization")).Return(s.Fixtures.PoolMgrMock, nil)
	s.Fixtures.PoolMgrCtrlMock.On("CreateOrgPoolManager", s.Fixtures.AdminContext, mock.AnythingOfType("params.Organization"), s.Fixtures.Providers, s.Fixtures.Store).Return(s.Fixtures.PoolMgrMock, nil)

	org, err := s.Runner.UpdateOrganization(s.Fixtures.AdminContext, s.Fixtures.StoreOrgs["test-org-1"].ID, s.Fixtures.UpdateRepoParams)

	s.Fixtures.PoolMgrMock.AssertExpectations(s.T())
	s.Fixtures.PoolMgrCtrlMock.AssertExpectations(s.T())
	s.Require().Nil(err)
	s.Require().Equal(s.Fixtures.UpdateRepoParams.CredentialsName, org.CredentialsName)
	s.Require().Equal(s.Fixtures.UpdateRepoParams.WebhookSecret, org.WebhookSecret)
}

func (s *OrgTestSuite) TestUpdateOrganizationErrUnauthorized() {
	_, err := s.Runner.UpdateOrganization(context.Background(), s.Fixtures.StoreOrgs["test-org-1"].ID, s.Fixtures.UpdateRepoParams)

	s.Require().Equal(runnerErrors.ErrUnauthorized, err)
}

func (s *OrgTestSuite) TestUpdateOrganizationFechFailed() {
	// corrupt database file to make sure that `r.store.GetOrganizationByID` fails unexpected.
	if err := os.WriteFile(s.Fixtures.DBFile, []byte("corrupted content"), os.ModeAppend); err != nil {
		s.Fail("cannot write to DB file: %s", s.Fixtures.DBFile)
	}

	_, err := s.Runner.UpdateOrganization(s.Fixtures.AdminContext, s.Fixtures.StoreOrgs["test-org-1"].ID, s.Fixtures.UpdateRepoParams)

	s.Require().Regexp("fetching org", err.Error())
}

func (s *OrgTestSuite) TestUpdateOrganizationInvalidCreds() {
	s.Fixtures.UpdateRepoParams.CredentialsName = "invalid-creds-name"

	_, err := s.Runner.UpdateOrganization(s.Fixtures.AdminContext, s.Fixtures.StoreOrgs["test-org-1"].ID, s.Fixtures.UpdateRepoParams)

	s.Require().Equal(runnerErrors.NewBadRequestError("invalid credentials (%s) for org %s", s.Fixtures.UpdateRepoParams.CredentialsName, s.Fixtures.StoreOrgs["test-org-1"].Name), err)
}

func (s *OrgTestSuite) TestUpdateOrganizationPoolMgrFailed() {
	s.Fixtures.PoolMgrCtrlMock.On("GetOrgPoolManager", mock.AnythingOfType("params.Organization")).Return(s.Fixtures.PoolMgrMock, s.Fixtures.ErrMock)
	s.Fixtures.PoolMgrMock.On("RefreshState", s.Fixtures.UpdatePoolStateParams).Return(s.Fixtures.ErrMock)

	_, err := s.Runner.UpdateOrganization(s.Fixtures.AdminContext, s.Fixtures.StoreOrgs["test-org-1"].ID, s.Fixtures.UpdateRepoParams)

	s.Fixtures.PoolMgrMock.AssertExpectations(s.T())
	s.Fixtures.PoolMgrCtrlMock.AssertExpectations(s.T())
	s.Require().Equal(fmt.Sprintf("updating org pool manager: %s", s.Fixtures.ErrMock.Error()), err.Error())
}

func (s *OrgTestSuite) TestUpdateOrganizationCreateOrgPoolMgrFailed() {
	s.Fixtures.PoolMgrCtrlMock.On("GetOrgPoolManager", mock.AnythingOfType("params.Organization")).Return(s.Fixtures.PoolMgrMock, nil)
	s.Fixtures.PoolMgrCtrlMock.On("CreateOrgPoolManager", s.Fixtures.AdminContext, mock.AnythingOfType("params.Organization"), s.Fixtures.Providers, s.Fixtures.Store).Return(s.Fixtures.PoolMgrMock, s.Fixtures.ErrMock)

	_, err := s.Runner.UpdateOrganization(s.Fixtures.AdminContext, s.Fixtures.StoreOrgs["test-org-1"].ID, s.Fixtures.UpdateRepoParams)

	s.Fixtures.PoolMgrMock.AssertExpectations(s.T())
	s.Fixtures.PoolMgrCtrlMock.AssertExpectations(s.T())
	s.Require().Equal(fmt.Sprintf("creating org pool manager: %s", s.Fixtures.ErrMock.Error()), err.Error())
}

func (s *OrgTestSuite) TestCreateOrgPool() {
	s.Fixtures.PoolMgrCtrlMock.On("GetOrgPoolManager", mock.AnythingOfType("params.Organization")).Return(s.Fixtures.PoolMgrMock, nil)

	pool, err := s.Runner.CreateOrgPool(s.Fixtures.AdminContext, s.Fixtures.StoreOrgs["test-org-1"].ID, s.Fixtures.CreatePoolParams)

	s.Fixtures.PoolMgrMock.AssertExpectations(s.T())
	s.Fixtures.PoolMgrCtrlMock.AssertExpectations(s.T())
	s.Require().Nil(err)
	s.Require().Equal(s.Fixtures.CreatePoolParams.ProviderName, pool.ProviderName)
}

// func (s *OrgTestSuite) TestCreateOrgPoolErrUnauthorized() {
// 	param, err := s.Runner.CreateOrgPool(s.Fixtures.Context, "org-id", s.Fixtures.CreatePoolParams)

// 	require.Equal(s.T(), params.Pool{}, param)
// 	require.Equal(s.T(), runnerErrors.ErrUnauthorized, err)
// }

// func (s *OrgTestSuite) TestCreateOrgPoolFetchOrgFailed() {
// 	s.Fixtures.StoreMock.On("GetOrganizationByID", s.Fixtures.AdminContext, "org-id").Return(s.Fixtures.Org, s.Fixtures.ErrMock)

// 	param, err := s.Runner.CreateOrgPool(s.Fixtures.AdminContext, "org-id", s.Fixtures.CreatePoolParams)

// 	s.Fixtures.StoreMock.AssertExpectations(s.T())
// 	require.Equal(s.T(), params.Pool{}, param)
// 	require.Equal(s.T(), fmt.Sprintf("fetching org: %s", s.Fixtures.ErrMock.Error()), err.Error())
// }

// func (s *OrgTestSuite) TestCreateOrgPoolErrNotFound() {
// 	s.Fixtures.StoreMock.On("GetOrganizationByID", s.Fixtures.AdminContext, "org-id").Return(s.Fixtures.Org, nil)
// 	s.Fixtures.PoolMgrCtrlMock.On("GetOrgPoolManager", s.Fixtures.Org).Return(s.Fixtures.PoolMgrMock, runnerErrors.ErrNotFound)

// 	pool, err := s.Runner.CreateOrgPool(s.Fixtures.AdminContext, "org-id", s.Fixtures.CreatePoolParams)

// 	s.Fixtures.StoreMock.AssertExpectations(s.T())
// 	s.Fixtures.PoolMgrMock.AssertExpectations(s.T())
// 	s.Fixtures.PoolMgrCtrlMock.AssertExpectations(s.T())
// 	require.Equal(s.T(), params.Pool{}, pool)
// 	require.Equal(s.T(), runnerErrors.ErrNotFound, err)
// }

// func (s *OrgTestSuite) TestCreateOrgPoolFetchPoolParamsFailed() {
// 	s.Fixtures.CreatePoolParams.ProviderName = ""

// 	s.Fixtures.StoreMock.On("GetOrganizationByID", s.Fixtures.AdminContext, "org-id").Return(s.Fixtures.Org, nil)
// 	s.Fixtures.PoolMgrCtrlMock.On("GetOrgPoolManager", s.Fixtures.Org).Return(s.Fixtures.PoolMgrMock, nil)

// 	pool, err := s.Runner.CreateOrgPool(s.Fixtures.AdminContext, "org-id", s.Fixtures.CreatePoolParams)

// 	s.Fixtures.StoreMock.AssertExpectations(s.T())
// 	s.Fixtures.PoolMgrMock.AssertExpectations(s.T())
// 	s.Fixtures.PoolMgrCtrlMock.AssertExpectations(s.T())
// 	require.Equal(s.T(), params.Pool{}, pool)
// 	require.Equal(s.T(), fmt.Sprintf("fetching pool params: validating params: missing provider: %s", runnerErrors.ErrBadRequest), err.Error())
// }

// func (s *OrgTestSuite) TestCreateOrgPoolFailed() {
// 	s.Fixtures.StoreMock.On("GetOrganizationByID", s.Fixtures.AdminContext, "org-id").Return(s.Fixtures.Org, nil)
// 	s.Fixtures.PoolMgrCtrlMock.On("GetOrgPoolManager", s.Fixtures.Org).Return(s.Fixtures.PoolMgrMock, nil)
// 	s.Fixtures.StoreMock.On("CreateOrganizationPool", s.Fixtures.AdminContext, "org-id", s.Fixtures.CreatePoolParams).Return(params.Pool{}, s.Fixtures.ErrMock)

// 	pool, err := s.Runner.CreateOrgPool(s.Fixtures.AdminContext, "org-id", s.Fixtures.CreatePoolParams)

// 	s.Fixtures.StoreMock.AssertExpectations(s.T())
// 	s.Fixtures.PoolMgrMock.AssertExpectations(s.T())
// 	s.Fixtures.PoolMgrCtrlMock.AssertExpectations(s.T())
// 	require.Equal(s.T(), params.Pool{}, pool)
// 	require.Equal(s.T(), fmt.Sprintf("creating pool: %s", s.Fixtures.ErrMock.Error()), err.Error())
// }

// func (s *OrgTestSuite) TestGetOrgPoolByID() {
// 	s.Fixtures.StoreMock.On("GetOrganizationPool", s.Fixtures.AdminContext, "org-id", "pool-id").Return(params.Pool{}, nil)

// 	pool, err := s.Runner.GetOrgPoolByID(s.Fixtures.AdminContext, "org-id", "pool-id")

// 	s.Fixtures.StoreMock.AssertExpectations(s.T())
// 	require.Equal(s.T(), params.Pool{}, pool)
// 	require.Nil(s.T(), err)
// }

// func (s *OrgTestSuite) TestGetOrgPoolByIDErrUnauthorized() {
// 	pool, err := s.Runner.GetOrgPoolByID(s.Fixtures.Context, "org-id", "pool-id")

// 	require.Equal(s.T(), params.Pool{}, pool)
// 	require.Equal(s.T(), runnerErrors.ErrUnauthorized, err)
// }

// func (s *OrgTestSuite) TestGetOrgPoolByIDFetchFailed() {
// 	s.Fixtures.StoreMock.On("GetOrganizationPool", s.Fixtures.AdminContext, "org-id", "pool-id").Return(params.Pool{}, s.Fixtures.ErrMock)

// 	pool, err := s.Runner.GetOrgPoolByID(s.Fixtures.AdminContext, "org-id", "pool-id")

// 	s.Fixtures.StoreMock.AssertExpectations(s.T())
// 	require.Equal(s.T(), params.Pool{}, pool)
// 	require.Equal(s.T(), fmt.Sprintf("fetching pool: %s", s.Fixtures.ErrMock.Error()), err.Error())
// }

// func (s *OrgTestSuite) TestDeleteOrgPool() {
// 	pool := params.Pool{ID: "pool-id"}

// 	s.Fixtures.StoreMock.On("GetOrganizationPool", s.Fixtures.AdminContext, "org-id", "pool-id").Return(pool, nil)
// 	s.Fixtures.StoreMock.On("ListPoolInstances", s.Fixtures.AdminContext, pool.ID).Return([]params.Instance{}, nil)
// 	s.Fixtures.StoreMock.On("DeleteOrganizationPool", s.Fixtures.AdminContext, "org-id", "pool-id").Return(nil)

// 	err := s.Runner.DeleteOrgPool(s.Fixtures.AdminContext, "org-id", "pool-id")

// 	s.Fixtures.StoreMock.AssertExpectations(s.T())
// 	require.Nil(s.T(), err)
// }

// func (s *OrgTestSuite) TestDeleteOrgPoolErrUnauthorized() {
// 	err := s.Runner.DeleteOrgPool(s.Fixtures.Context, "org-id", "pool-id")

// 	require.Equal(s.T(), runnerErrors.ErrUnauthorized, err)
// }

// func (s *OrgTestSuite) TestDeleteOrgPoolFetchPoolFailed() {
// 	s.Fixtures.StoreMock.On("GetOrganizationPool", s.Fixtures.AdminContext, "org-id", "pool-id").Return(params.Pool{}, s.Fixtures.ErrMock)

// 	err := s.Runner.DeleteOrgPool(s.Fixtures.AdminContext, "org-id", "pool-id")

// 	s.Fixtures.StoreMock.AssertExpectations(s.T())
// 	require.Equal(s.T(), fmt.Sprintf("fetching pool: %s", s.Fixtures.ErrMock.Error()), err.Error())
// }

// func (s *OrgTestSuite) TestDeleteOrgPoolFetchInstancesFailed() {
// 	pool := params.Pool{ID: "pool-id"}

// 	s.Fixtures.StoreMock.On("GetOrganizationPool", s.Fixtures.AdminContext, "org-id", "pool-id").Return(pool, nil)
// 	s.Fixtures.StoreMock.On("ListPoolInstances", s.Fixtures.AdminContext, pool.ID).Return([]params.Instance{}, s.Fixtures.ErrMock)

// 	err := s.Runner.DeleteOrgPool(s.Fixtures.AdminContext, "org-id", "pool-id")

// 	s.Fixtures.StoreMock.AssertExpectations(s.T())
// 	require.Equal(s.T(), fmt.Sprintf("fetching instances: %s", s.Fixtures.ErrMock.Error()), err.Error())
// }

// func (s *OrgTestSuite) TestDeleteOrgPoolRunnersFailed() {
// 	pool := params.Pool{ID: "pool-id"}
// 	poolInstances := []params.Instance{
// 		{ID: "runner-id-1"},
// 		{ID: "runner-id-2"},
// 		{ID: "runner-id-3"},
// 	}

// 	s.Fixtures.StoreMock.On("GetOrganizationPool", s.Fixtures.AdminContext, "org-id", "pool-id").Return(pool, nil)
// 	s.Fixtures.StoreMock.On("ListPoolInstances", s.Fixtures.AdminContext, pool.ID).Return(poolInstances, nil)

// 	err := s.Runner.DeleteOrgPool(s.Fixtures.AdminContext, "org-id", "pool-id")

// 	s.Fixtures.StoreMock.AssertExpectations(s.T())
// 	require.Equal(s.T(), runnerErrors.NewBadRequestError("pool has runners: runner-id-1, runner-id-2, runner-id-3"), err)
// }

// func (s *OrgTestSuite) TestDeleteOrgPoolFailed() {
// 	pool := params.Pool{ID: "pool-id"}

// 	s.Fixtures.StoreMock.On("GetOrganizationPool", s.Fixtures.AdminContext, "org-id", "pool-id").Return(pool, nil)
// 	s.Fixtures.StoreMock.On("ListPoolInstances", s.Fixtures.AdminContext, pool.ID).Return([]params.Instance{}, nil)
// 	s.Fixtures.StoreMock.On("DeleteOrganizationPool", s.Fixtures.AdminContext, "org-id", "pool-id").Return(s.Fixtures.ErrMock)

// 	err := s.Runner.DeleteOrgPool(s.Fixtures.AdminContext, "org-id", "pool-id")

// 	s.Fixtures.StoreMock.AssertExpectations(s.T())
// 	require.Equal(s.T(), fmt.Sprintf("deleting pool: %s", s.Fixtures.ErrMock.Error()), err.Error())
// }

// func (s *OrgTestSuite) TestListOrgPools() {
// 	s.Fixtures.StoreMock.On("ListOrgPools", s.Fixtures.AdminContext, "org-id").Return([]params.Pool{}, nil)

// 	pool, err := s.Runner.ListOrgPools(s.Fixtures.AdminContext, "org-id")

// 	s.Fixtures.StoreMock.AssertExpectations(s.T())
// 	require.Equal(s.T(), []params.Pool{}, pool)
// 	require.Nil(s.T(), err)
// }

// func (s *OrgTestSuite) TestListOrgPoolsErrUnauthorized() {
// 	pool, err := s.Runner.ListOrgPools(s.Fixtures.Context, "org-id")

// 	require.Equal(s.T(), []params.Pool{}, pool)
// 	require.Equal(s.T(), runnerErrors.ErrUnauthorized, err)
// }

// func (s *OrgTestSuite) TestListOrgPoolsFetchFailed() {
// 	s.Fixtures.StoreMock.On("ListOrgPools", s.Fixtures.AdminContext, "org-id").Return([]params.Pool{}, s.Fixtures.ErrMock)

// 	pool, err := s.Runner.ListOrgPools(s.Fixtures.AdminContext, "org-id")

// 	s.Fixtures.StoreMock.AssertExpectations(s.T())
// 	require.Nil(s.T(), pool)
// 	require.Equal(s.T(), fmt.Sprintf("fetching pools: %s", s.Fixtures.ErrMock.Error()), err.Error())
// }

// func (s *OrgTestSuite) TestUpdateOrgPool() {
// 	s.Fixtures.StoreMock.On("GetOrganizationPool", s.Fixtures.AdminContext, "org-id", "pool-id").Return(params.Pool{}, nil)
// 	s.Fixtures.StoreMock.On("UpdateOrganizationPool", s.Fixtures.AdminContext, "org-id", "pool-id", params.UpdatePoolParams{}).Return(params.Pool{}, nil)

// 	newPool, err := s.Runner.UpdateOrgPool(s.Fixtures.AdminContext, "org-id", "pool-id", params.UpdatePoolParams{})

// 	s.Fixtures.StoreMock.AssertExpectations(s.T())
// 	require.Equal(s.T(), params.Pool{}, newPool)
// 	require.Nil(s.T(), err)
// }

// func (s *OrgTestSuite) TestUpdateOrgPoolErrUnauthorized() {
// 	param, err := s.Runner.UpdateOrgPool(s.Fixtures.Context, "org-id", "pool-id", params.UpdatePoolParams{})

// 	require.Equal(s.T(), params.Pool{}, param)
// 	require.Equal(s.T(), runnerErrors.ErrUnauthorized, err)
// }

// func (s *OrgTestSuite) TestUpdateOrgPoolFetchFailed() {
// 	s.Fixtures.StoreMock.On("GetOrganizationPool", s.Fixtures.AdminContext, "org-id", "pool-id").Return(params.Pool{}, s.Fixtures.ErrMock)

// 	param, err := s.Runner.UpdateOrgPool(s.Fixtures.AdminContext, "org-id", "pool-id", params.UpdatePoolParams{})

// 	s.Fixtures.StoreMock.AssertExpectations(s.T())
// 	require.Equal(s.T(), params.Pool{}, param)
// 	require.Equal(s.T(), fmt.Sprintf("fetching pool: %s", s.Fixtures.ErrMock.Error()), err.Error())
// }

// func (s *OrgTestSuite) TestUpdateOrgPoolCompareFailed() {
// 	pool := params.Pool{
// 		MaxRunners:     1,
// 		MinIdleRunners: 6,
// 	}
// 	UpdatePoolParams := params.UpdatePoolParams{
// 		MaxRunners:     &pool.MaxRunners,
// 		MinIdleRunners: &pool.MinIdleRunners,
// 	}

// 	s.Fixtures.StoreMock.On("GetOrganizationPool", s.Fixtures.AdminContext, "org-id", "pool-id").Return(params.Pool{}, nil)

// 	pool, err := s.Runner.UpdateOrgPool(s.Fixtures.AdminContext, "org-id", "pool-id", UpdatePoolParams)

// 	s.Fixtures.StoreMock.AssertExpectations(s.T())
// 	require.Equal(s.T(), params.Pool{}, pool)
// 	require.Equal(s.T(), runnerErrors.NewBadRequestError("min_idle_runners cannot be larger than max_runners"), err)
// }

// func (s *OrgTestSuite) TestUpdateOrgPoolFailed() {
// 	s.Fixtures.StoreMock.On("GetOrganizationPool", s.Fixtures.AdminContext, "org-id", "pool-id").Return(params.Pool{}, nil)
// 	s.Fixtures.StoreMock.On("UpdateOrganizationPool", s.Fixtures.AdminContext, "org-id", "pool-id", params.UpdatePoolParams{}).Return(params.Pool{}, s.Fixtures.ErrMock)

// 	newPool, err := s.Runner.UpdateOrgPool(s.Fixtures.AdminContext, "org-id", "pool-id", params.UpdatePoolParams{})

// 	s.Fixtures.StoreMock.AssertExpectations(s.T())
// 	require.Equal(s.T(), params.Pool{}, newPool)
// 	require.Equal(s.T(), fmt.Sprintf("updating pool: %s", s.Fixtures.ErrMock.Error()), err.Error())
// }

// func (s *OrgTestSuite) TestListOrgInstances() {
// 	s.Fixtures.StoreMock.On("ListOrgInstances", s.Fixtures.AdminContext, "org-id").Return([]params.Instance{}, nil)

// 	instance, err := s.Runner.ListOrgInstances(s.Fixtures.AdminContext, "org-id")

// 	s.Fixtures.StoreMock.AssertExpectations(s.T())
// 	require.Equal(s.T(), []params.Instance{}, instance)
// 	require.Nil(s.T(), err)
// }

// func (s *OrgTestSuite) TestListOrgInstancesErrUnauthorized() {
// 	instance, err := s.Runner.ListOrgInstances(s.Fixtures.Context, "org-id")

// 	require.Nil(s.T(), instance)
// 	require.Equal(s.T(), runnerErrors.ErrUnauthorized, err)
// }

// func (s *OrgTestSuite) TestListOrgFetchInstancesFailed() {
// 	s.Fixtures.StoreMock.On("ListOrgInstances", s.Fixtures.AdminContext, "org-id").Return([]params.Instance{}, s.Fixtures.ErrMock)

// 	instance, err := s.Runner.ListOrgInstances(s.Fixtures.AdminContext, "org-id")

// 	s.Fixtures.StoreMock.AssertExpectations(s.T())
// 	require.Equal(s.T(), []params.Instance{}, instance)
// 	require.Equal(s.T(), fmt.Sprintf("fetching instances: %s", s.Fixtures.ErrMock.Error()), err.Error())
// }

// func (s *OrgTestSuite) TestFindOrgPoolManager() {
// 	s.Fixtures.StoreMock.On("GetOrganization", s.Fixtures.AdminContext, "org-id").Return(s.Fixtures.Org, nil)
// 	s.Fixtures.PoolMgrCtrlMock.On("GetOrgPoolManager", s.Fixtures.Org).Return(s.Fixtures.PoolMgrMock, nil)

// 	poolManager, err := s.Runner.findOrgPoolManager("org-id")

// 	s.Fixtures.StoreMock.AssertExpectations(s.T())
// 	s.Fixtures.PoolMgrMock.AssertExpectations(s.T())
// 	s.Fixtures.PoolMgrCtrlMock.AssertExpectations(s.T())
// 	require.Equal(s.T(), s.Fixtures.PoolMgrMock, poolManager)
// 	require.Nil(s.T(), err)
// }

// func (s *OrgTestSuite) TestFindOrgPoolManagerFetchFailed() {
// 	s.Fixtures.StoreMock.On("GetOrganization", s.Fixtures.AdminContext, "org-id").Return(s.Fixtures.Org, s.Fixtures.ErrMock)

// 	org, err := s.Runner.findOrgPoolManager("org-id")

// 	s.Fixtures.StoreMock.AssertExpectations(s.T())
// 	require.Nil(s.T(), org)
// 	require.Equal(s.T(), fmt.Sprintf("fetching org: %s", s.Fixtures.ErrMock.Error()), err.Error())
// }

// func (s *OrgTestSuite) TestFindOrgPoolManagerFetchPoolMgrFailed() {
// 	s.Fixtures.StoreMock.On("GetOrganization", s.Fixtures.AdminContext, "org-id").Return(s.Fixtures.Org, nil)
// 	s.Fixtures.PoolMgrCtrlMock.On("GetOrgPoolManager", s.Fixtures.Org).Return(s.Fixtures.PoolMgrMock, s.Fixtures.ErrMock)

// 	poolManager, err := s.Runner.findOrgPoolManager("org-id")

// 	s.Fixtures.StoreMock.AssertExpectations(s.T())
// 	s.Fixtures.PoolMgrMock.AssertExpectations(s.T())
// 	s.Fixtures.PoolMgrCtrlMock.AssertExpectations(s.T())
// 	require.Nil(s.T(), poolManager)
// 	require.Equal(s.T(), fmt.Sprintf("fetching pool manager for org: %s", s.Fixtures.ErrMock.Error()), err.Error())
// }

func TestOrgTestSuite(t *testing.T) {
	suite.Run(t, new(OrgTestSuite))
}
