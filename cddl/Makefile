CONCATENATED_SUIT_CDDL       := suit-manifest.cddl
SUIT_MANIFEST_CDDL           := draft-ietf-suit-manifest.cddl
SUIT_TRUST_DOMAINS_CDDL      := draft-ietf-suit-trust-domains.cddl
SUIT_UPDATE_MANAGEMENT_CDDL  := draft-ietf-suit-update-management.cddl
SUIT_ENCRYPTED_PAYLOADS_CDDL := draft-ietf-suit-firmware-encryption.cddl
SUIT_REPORT_CDDL             := draft-ietf-suit-report.cddl
SUIT_MTI_CDDL                := draft-ietf-suit-mti.cddl
COSWID_CDDL                  := rfc-9393-coswid.cddl
COSE_XML                     := rfc-9052-cose.xml
COSE_CDDL                    := rfc-9052-cose.cddl

CONCATENATED_TEEP_CDDL       := teep-protocol.cddl
TEEP_PROTOCOL_CDDL           := draft-ietf-teep-protocol.cddl

CONCATENATED_PSA_TOKEN_CDDL  := psa-token.cddl

.PHONY: cat-cddl
cat-cddl: $(CONCATENATED_SUIT_CDDL) $(CONCATENATED_TEEP_CDDL) $(CONCATENATED_PSA_TOKEN_CDDL)

$(CONCATENATED_SUIT_CDDL): $(SUIT_MANIFEST_CDDL) $(SUIT_TRUST_DOMAINS_CDDL) $(SUIT_UPDATE_MANAGEMENT_CDDL) $(SUIT_ENCRYPTED_PAYLOADS_CDDL) $(SUIT_REPORT_CDDL) $(SUIT_MTI_CDDL) $(COSWID_CDDL) $(COSE_CDDL)
	cat $^ > $@

$(SUIT_MANIFEST_CDDL):
	curl https://raw.githubusercontent.com/suit-wg/manifest-spec/master/draft-ietf-suit-manifest.cddl -o $@

$(SUIT_TRUST_DOMAINS_CDDL):
	curl https://raw.githubusercontent.com/suit-wg/suit-multiple-trust-domains/main/draft-ietf-suit-trust-domains.cddl -o $@

$(SUIT_UPDATE_MANAGEMENT_CDDL):
	curl https://raw.githubusercontent.com/suit-wg/suit-update-management/refs/heads/master/draft-ietf-suit-update-management.cddl | \
	sed -i -e 's/suit-current-version => \\/suit-current-version =>/' $@

$(SUIT_ENCRYPTED_PAYLOADS_CDDL):
	curl https://raw.githubusercontent.com/suit-wg/suit-firmware-encryption/main/draft-ietf-suit-firmware-encryption.cddl -o $@


$(SUIT_REPORT_CDDL):
	curl https://raw.githubusercontent.com/suit-wg/suit-report/main/draft-ietf-suit-report.cddl -o $@

$(SUIT_MTI_CDDL):
	curl https://raw.githubusercontent.com/suit-wg/suit-mti/main/draft-ietf-suit-mti.cddl -o $@

$(COSWID_CDDL):
	curl https://raw.githubusercontent.com/sacmwg/draft-ietf-sacm-coswid/refs/heads/master/concise-swid-tag.cddl | sed -e 's/label /coswid-label /g' > $@

$(COSE_XML):
	curl https://www.rfc-editor.org/rfc/rfc9052.xml -o $@

$(COSE_CDDL): $(COSE_XML)
	sed -n -e '/<sourcecode type="cddl"/,/<\/sourcecode>/ p' $< | sed -e '/<sourcecode type="cddl"/ d' -e '/<\/sourcecode>/ d' -e 's/\&lt;/</g' -e 's/\&gt;/>/g' > $@

$(TEEP_PROTOCOL_CDDL):
	curl https://raw.githubusercontent.com/ietf-teep/teep-protocol/refs/heads/master/draft-ietf-teep-protocol.cddl -o $@

$(CONCATENATED_TEEP_CDDL): $(TEEP_PROTOCOL_CDDL) $(SUIT_MANIFEST_CDDL) $(SUIT_TRUST_DOMAINS_CDDL) $(SUIT_UPDATE_MANAGEMENT_CDDL) $(SUIT_ENCRYPTED_PAYLOADS_CDDL) $(SUIT_REPORT_CDDL) $(SUIT_MTI_CDDL) $(COSWID_CDDL) $(COSE_CDDL)
	cat $^ > $@

$(CONCATENATED_PSA_TOKEN_CDDL):
	make -C ./draft-psa-token/cddl/ psa-attestation.cddl
	sed -e 's/psa-profile-type = "tag:psacertified.org,2023:psa#tfm"/psa-profile-type = tstr/' < ./draft-psa-token/cddl/psa-attestation.cddl > $(CONCATENATED_PSA_TOKEN_CDDL)

.PHONY: clean
clean:
	$(RM) *.cddl
