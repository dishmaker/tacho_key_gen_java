package com.ults.jrc.tachograph.keytool;

import static com.ults.jrc.tachograph.keytool.TachographDefinitions.*;
import java.util.Arrays;
import java.util.List;

/**
 * Enumeration of supported tachograph certificate types.
 *
 * @author Klaas Mateboer
 */
public enum TachographCertificateType {
    ERCA("erca",
            AUTHORISATION_TYPE_ERCA,
            EQUIPMENT_TYPE_ERCA,
            CERTIFICATE_VALIDITY_ERCA),
    ERCA_LINK("erca_link",
            AUTHORISATION_TYPE_ERCA,
            EQUIPMENT_TYPE_ERCA,
            CERTIFICATE_VALIDITY_ERCA_LINK,
            ERCA),
    MSCA_VU_EGF("msca_vu_egf", 
            AUTHORISATION_TYPE_MSCA, 
            EQUIPMENT_TYPE_MSCA, 
            CERTIFICATE_VALIDITY_MSCA_VU_EGF,
            ERCA),
    MSCA_CARD("msca_card", 
            AUTHORISATION_TYPE_MSCA, 
            EQUIPMENT_TYPE_MSCA, 
            CERTIFICATE_VALIDITY_MSCA_CARD, 
            ERCA),
    DRIVER_CARD_MA("driver_card_ma", 
            AUTHORISATION_TYPE_DRIVER_CARD_MA, 
            EQUIPMENT_TYPE_DRIVER_CARD,
            CERTIFICATE_VALIDITY_DRIVER_CARD_MA, 
            MSCA_CARD),
    DRIVER_CARD_SIGN("driver_card_sign", 
            AUTHORISATION_TYPE_DRIVER_CARD_SIGN, 
            EQUIPMENT_TYPE_DRIVER_CARD,
            CERTIFICATE_VALIDITY_DRIVER_CARD_SIGN, 
            MSCA_CARD),
    WORKSHOP_CARD_MA("workshop_card_ma", 
            AUTHORISATION_TYPE_WORKSHOP_CARD_MA, 
            EQUIPMENT_TYPE_WORKSHOP_CARD, 
            CERTIFICATE_VALIDITY_WORKSHOP_CARD_MA, 
            MSCA_CARD),
    WORKSHOP_CARD_SIGN("workshop_card_sign", 
            AUTHORISATION_TYPE_WORKSHOP_CARD_SIGN, 
            EQUIPMENT_TYPE_WORKSHOP_CARD, 
            CERTIFICATE_VALIDITY_WORKSHOP_CARD_SIGN,
            MSCA_CARD),
    CONTROL_CARD_MA("control_card_ma", 
            AUTHORISATION_TYPE_CONTROL_CARD_MA, 
            EQUIPMENT_TYPE_CONTROL_CARD, 
            CERTIFICATE_VALIDITY_CONTROL_CARD_MA,
            MSCA_CARD),
    COMPANY_CARD_MA("company_card_ma", 
            AUTHORISATION_TYPE_COMPANY_CARD_MA, 
            EQUIPMENT_TYPE_COMPANY_CARD, 
            CERTIFICATE_VALIDITY_COMPANY_CARD_MA,
            MSCA_CARD),
    VU_MA("vu_ma",
            AUTHORISATION_TYPE_VU_MA,
            EQUIPMENT_TYPE_VU, 
            CERTIFICATE_VALIDITY_VU_MA, 
            MSCA_VU_EGF),
    VU_SIGN("vu_sign",
            AUTHORISATION_TYPE_VU_SIGN,
            EQUIPMENT_TYPE_VU, 
            CERTIFICATE_VALIDITY_VU_SIGN,
            MSCA_VU_EGF),
    EGF_MA("egf_ma",
            AUTHORISATION_TYPE_EGF_MA,
            EQUIPMENT_TYPE_EGF,
            CERTIFICATE_VALIDITY_EGF_MA,
            MSCA_VU_EGF);

    static final List<TachographCertificateType> CA_TYPES = Arrays.asList(
            ERCA, MSCA_CARD, MSCA_VU_EGF);
    static final List<TachographCertificateType> EQUIPMENT_TYPES = Arrays.asList(
            DRIVER_CARD_MA, DRIVER_CARD_SIGN, WORKSHOP_CARD_MA, WORKSHOP_CARD_SIGN, CONTROL_CARD_MA, COMPANY_CARD_MA,
            VU_MA, VU_SIGN, EGF_MA);
    static final List<TachographCertificateType> REQUEST_TYPES = Arrays.asList(
            VU_MA, VU_SIGN);

    private final String name;
    final byte authorisationType;
    final byte equipmentType;
    final int validity;
    final TachographCertificateType signer;

    TachographCertificateType(String name, byte authorisationType, byte equipmentType, int validity) {
        this.name = name;
        this.authorisationType = authorisationType;
        this.equipmentType = equipmentType;
        this.validity = validity;
        this.signer = this;
    }
    
    TachographCertificateType(String name, byte authorisationType, byte equipmentType, int validity, TachographCertificateType signer) {
        this.name = name;
        this.authorisationType = authorisationType;
        this.equipmentType = equipmentType;
        this.validity = validity;
        this.signer = signer;
    }

    String getName() {
        return name;
    }

    @Override
    public String toString() {
        return name;
    }
}