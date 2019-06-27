package psst

import "github.com/google/uuid"

type Generator interface {
	Generate() string
}

type SecretMetadata struct {
	/*
		{
		  "data": {
		    "created_time": "2018-03-22T02:24:06.945319214Z",
		    "current_version": 3,
		    "max_versions": 0,
		    "oldest_version": 0,
		    "updated_time": "2018-03-22T02:36:43.986212308Z",
		    "versions": {
		      "1": {
		        "created_time": "2018-03-22T02:24:06.945319214Z",
		        "deletion_time": "",
		        "destroyed": false
		      },
		      "2": {
		        "created_time": "2018-03-22T02:36:33.954880664Z",
		        "deletion_time": "",
		        "destroyed": false
		      },
		      "3": {
		        "created_time": "2018-03-22T02:36:43.986212308Z",
		        "deletion_time": "",
		        "destroyed": false
		      }
		    }
		  }
		}
	*/

}

type Secret struct {
	Name        string         `json:"name"`
	Path        string         `json:"path"`
	ID          uuid.UUID      `json:"id"`
	Generator   Generator      `json:"generator"`
	DevValue    string         `json:"dev_value"`
	DevMetadata SecretMetadata `json:"dev_metadata"`

	PreProdValue    string
	PreProdMetadata SecretMetadata

	ProdValue    string
	ProdMetadata SecretMetadata
}

type Role struct {
	Name    string
	ID      uuid.UUID
	Secrets []string
}
