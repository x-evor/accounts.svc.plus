package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"account/internal/service"
)

type homepageVideoEntryPayload struct {
	Domain    string `json:"domain,omitempty"`
	VideoURL  string `json:"videoUrl"`
	PosterURL string `json:"posterUrl"`
}

func toHomepageVideoEntryPayload(entry service.HomepageVideoEntry) homepageVideoEntryPayload {
	return homepageVideoEntryPayload{
		Domain:    strings.TrimSpace(entry.DomainKey),
		VideoURL:  strings.TrimSpace(entry.VideoURL),
		PosterURL: strings.TrimSpace(entry.PosterURL),
	}
}

func (h *handler) getHomepageVideoPublic(c *gin.Context) {
	entry, err := service.ResolveHomepageVideoEntry(c.Request.Context(), h.resolveTenantHost(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"resolved": toHomepageVideoEntryPayload(entry),
	})
}

func (h *handler) getHomepageVideoSettings(c *gin.Context) {
	if _, ok := h.requireAdminPermission(c, permissionAdminSettingsRead); !ok {
		return
	}

	settings, err := service.GetHomepageVideoSettings(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	overrides := make([]homepageVideoEntryPayload, 0, len(settings.Overrides))
	for _, item := range settings.Overrides {
		overrides = append(overrides, toHomepageVideoEntryPayload(item))
	}

	c.JSON(http.StatusOK, gin.H{
		"defaultEntry": toHomepageVideoEntryPayload(settings.DefaultEntry),
		"overrides":    overrides,
	})
}

func (h *handler) updateHomepageVideoSettings(c *gin.Context) {
	adminUser, ok := h.requireAdminPermission(c, permissionAdminSettingsWrite)
	if !ok {
		return
	}
	if h.isReadOnlyAccount(adminUser) {
		respondError(c, http.StatusForbidden, "read_only_account", "demo account is read-only")
		return
	}

	var req struct {
		DefaultEntry homepageVideoEntryPayload   `json:"defaultEntry"`
		Overrides    []homepageVideoEntryPayload `json:"overrides"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	overrides := make([]service.HomepageVideoEntry, 0, len(req.Overrides))
	for _, item := range req.Overrides {
		overrides = append(overrides, service.HomepageVideoEntry{
			DomainKey: item.Domain,
			VideoURL:  item.VideoURL,
			PosterURL: item.PosterURL,
		})
	}

	settings, err := service.SaveHomepageVideoSettings(c.Request.Context(), service.HomepageVideoSettings{
		DefaultEntry: service.HomepageVideoEntry{
			VideoURL:  req.DefaultEntry.VideoURL,
			PosterURL: req.DefaultEntry.PosterURL,
		},
		Overrides: overrides,
	}, adminUser.Email)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, service.ErrServiceDBNotInitialized) {
			status = http.StatusServiceUnavailable
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	responseOverrides := make([]homepageVideoEntryPayload, 0, len(settings.Overrides))
	for _, item := range settings.Overrides {
		responseOverrides = append(responseOverrides, toHomepageVideoEntryPayload(item))
	}

	c.JSON(http.StatusOK, gin.H{
		"defaultEntry": toHomepageVideoEntryPayload(settings.DefaultEntry),
		"overrides":    responseOverrides,
	})
}
