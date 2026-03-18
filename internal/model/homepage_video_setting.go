package model

import (
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// HomepageVideoSetting stores the homepage product demo media config.
type HomepageVideoSetting struct {
	UUID      string    `gorm:"column:uuid;type:uuid;primaryKey"`
	DomainKey string    `gorm:"column:domain_key;type:text;not null;uniqueIndex:idx_homepage_video_domain_key"`
	VideoURL  string    `gorm:"column:video_url;type:text;not null"`
	PosterURL string    `gorm:"column:poster_url;type:text;not null;default:''"`
	UpdatedBy string    `gorm:"column:updated_by;type:text;not null;default:''"`
	CreatedAt time.Time `gorm:"column:created_at;not null;autoCreateTime"`
	UpdatedAt time.Time `gorm:"column:updated_at;not null;autoUpdateTime"`
}

func (HomepageVideoSetting) TableName() string { return "homepage_video_settings" }

func (setting *HomepageVideoSetting) BeforeCreate(tx *gorm.DB) error {
	if strings.TrimSpace(setting.UUID) == "" {
		setting.UUID = uuid.NewString()
	}
	return nil
}
