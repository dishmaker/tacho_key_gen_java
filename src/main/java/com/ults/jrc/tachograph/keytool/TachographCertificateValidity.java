package com.ults.jrc.tachograph.keytool;

import java.time.LocalDateTime;

/**
 * Immutable representation of a certificate validity period.
 *
 * @author Klaas Mateboer
 */
public class TachographCertificateValidity {

    final LocalDateTime effectiveDate;
    final LocalDateTime expirationDate;

    static TachographCertificateValidity getInstance(LocalDateTime effectiveDate, LocalDateTime expirationDate) {
        return new TachographCertificateValidity(effectiveDate, expirationDate);
    }

    static TachographCertificateValidity getInstance(LocalDateTime effectiveDate, TachographCertificateType type) {
        return new TachographCertificateValidity(effectiveDate, effectiveDate.plusMonths(type.validity));
    }

    private TachographCertificateValidity(LocalDateTime effectiveDate, LocalDateTime expirationDate) {
        this.effectiveDate = effectiveDate;
        this.expirationDate = expirationDate;
    }
}
