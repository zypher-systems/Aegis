package configsvc

import (
	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
	"github.com/zypher-systems/aegis/services/api/internal/store"
)

func attachWAFProfile(pb *aegisv1.Host, p *store.WAFProfile) {
	if pb == nil || p == nil {
		return
	}
	pb.WafEnabled = true
	pb.WafMode = p.Mode
	pb.WafParanoia = uint32(p.Paranoia)
	pb.WafInboundThreshold = uint32(p.InboundThreshold)
	pb.WafBodyLimitBytes = uint32(p.BodyLimitBytes)
	pb.WafAllowedMethods = append([]string(nil), p.AllowedMethods...)
	pb.WafAllowedContentTypes = append([]string(nil), p.AllowedContentTypes...)
	pb.WafAnyContentType = p.AnyContentType
	pb.WafRestrictedHeaders = append([]string(nil), p.RestrictedHeaders...)
	pb.WafDisabledTags = append([]string(nil), p.DisabledTags...)
	for _, e := range p.Exclusions {
		pb.WafExclusions = append(pb.WafExclusions, &aegisv1.WAFExclusion{
			RuleId: e.RuleID,
			Path:   e.Path,
			Target: e.Target,
		})
	}
}
