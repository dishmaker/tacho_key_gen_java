package com.ults.jrc.tachograph.samples;

import static com.ults.jrc.tachograph.keytool.TachographKeyToolCli.process;

import org.junit.Test;

public class SamplesUtoTest {

    @Test
    public void verifyMscaUto11() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (1-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert"
        );
    }

    @Test
    public void verifyMscaUto12() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (1-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert"
        );
    }

    @Test
    public void verifyMscaUto21() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (2-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (2).cert"
        );
    }

    @Test
    public void verifyMscaUto22() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (2-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (2).cert"
        );
    }

    @Test
    public void verifyMscaUto31() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (3-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (3).cert");
    }

    @Test
    public void verifyMscaUtoEgf11() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/EGF/UTO_EGF_MA (1-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_VU-EGF (1-1).cert");
    }

    @Test
    public void verifyMscaUtoEgf12() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/EGF/UTO_EGF_MA (1-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_VU-EGF (1-2).cert");
    }

    @Test
    public void verifyMscaUtoEgf21() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/EGF/UTO_EGF_MA (2-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_VU-EGF (2-1).cert");
    }

    @Test
    public void verifyMscaUtoEgf22() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/EGF/UTO_EGF_MA (2-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_VU-EGF (2-2).cert");
    }

    @Test
    public void verifyMscaUtoEgf31() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/EGF/UTO_EGF_MA (3-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_VU-EGF (3-1).cert");
    }

    @Test
    public void verifyMscaUtoVuMa11() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/VU/UTO_VU_MA (1-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_VU-EGF (1-1).cert");
    }

    @Test
    public void verifyMscaUtoVuMa12() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/VU/UTO_VU_MA (1-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_VU-EGF (1-2).cert");
    }

    @Test
    public void verifyMscaUtoVuMa21() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/VU/UTO_VU_MA (2-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_VU-EGF (2-1).cert");
    }

    @Test
    public void verifyMscaUtoVuMa22() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/VU/UTO_VU_MA (2-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_VU-EGF (2-2).cert");
    }

    @Test
    public void verifyMscaUtoVuMa31() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/VU/UTO_VU_MA (3-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_VU-EGF (3-1).cert");
    }

    @Test
    public void verifyMscaUtoVuSign11() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/VU/UTO_VU_Sign (1-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_VU-EGF (1-1).cert");
    }

    @Test
    public void verifyMscaUtoVuSign12() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/VU/UTO_VU_Sign (1-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_VU-EGF (1-2).cert");
    }

    @Test
    public void verifyMscaUtoVuSign21() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/VU/UTO_VU_Sign (2-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_VU-EGF (2-1).cert");
    }

    @Test
    public void verifyMscaUtoVuSign22() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/VU/UTO_VU_Sign (2-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_VU-EGF (2-2).cert");
    }

    @Test
    public void verifyMscaUtoVuSign31() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/VU/UTO_VU_Sign (3-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_VU-EGF (3-1).cert");
    }

    @Test
    public void verifyMscaUtoCompanyCardMa11() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Company_Card_MA (1-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (1-1).cert");
    }

    @Test
    public void verifyMscaUtoCompanyCardMa12() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Company_Card_MA (1-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (1-2).cert");
    }

    @Test
    public void verifyMscaUtoCompanyCardMa21() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Company_Card_MA (2-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (2-1).cert");
    }

    @Test
    public void verifyMscaUtoCompanyCardMa22() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Company_Card_MA (2-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (2-2).cert");
    }

    @Test
    public void verifyMscaUtoCompanyCardMa31() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Company_Card_MA (3-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (3-1).cert");
    }

    @Test
    public void verifyMscaUtoControlCardMa11() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Control_Card_MA (1-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (1-1).cert");
    }

    @Test
    public void verifyMscaUtoControlCardMa12() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Control_Card_MA (1-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (1-2).cert");
    }

    @Test
    public void verifyMscaUtoControlCardMa21() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Control_Card_MA (2-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (2-1).cert");
    }

    @Test
    public void verifyMscaUtoControlCardMa22() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Control_Card_MA (2-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (2-2).cert");
    }

    @Test
    public void verifyMscaUtoControlCardMa31() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Control_Card_MA (3-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (3-1).cert");
    }

    @Test
    public void verifyMscaUtoDriverCardMa11() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Driver_Card_MA (1-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (1-1).cert");
    }

    @Test
    public void verifyMscaUtoDriverCardMa12() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Driver_Card_MA (1-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (1-2).cert");
    }

    @Test
    public void verifyMscaUtoDriverCardMa21() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Driver_Card_MA (2-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (2-1).cert");
    }

    @Test
    public void verifyMscaUtoDriverCardMa22() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Driver_Card_MA (2-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (2-2).cert");
    }

    @Test
    public void verifyMscaUtoDriverCardMa31() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Driver_Card_MA (3-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (3-1).cert");
    }

    @Test
    public void verifyMscaUtoDriverCardSign11() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Driver_Card_Sign (1-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (1-1).cert");
    }

    @Test
    public void verifyMscaUtoDriverCardSign12() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Driver_Card_Sign (1-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (1-2).cert");
    }

    @Test
    public void verifyMscaUtoDriverCardSign21() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Driver_Card_Sign (2-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (2-1).cert");
    }

    @Test
    public void verifyMscaUtoDriverCardSign22() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Driver_Card_Sign (2-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (2-2).cert");
    }

    @Test
    public void verifyMscaUtoDriverCardSign31() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Driver_Card_Sign (3-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (3-1).cert");
    }

    @Test
    public void verifyMscaUtoWorkshopCardMa11() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Workshop_Card_MA (1-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (1-1).cert");
    }

    @Test
    public void verifyMscaUtoWorkshopCardMa12() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Workshop_Card_MA (1-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (1-2).cert");
    }

    @Test
    public void verifyMscaUtoWorkshopCardMa21() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Workshop_Card_MA (2-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (2-1).cert");
    }

    @Test
    public void verifyMscaUtoWorkshopCardMa22() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Workshop_Card_MA (2-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (2-2).cert");
    }

    @Test
    public void verifyMscaUtoWorkshopCardMa31() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Workshop_Card_MA (3-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (3-1).cert");
    }

    @Test
    public void verifyMscaUtoWorkshopCardSign11() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Workshop_Card_Sign (1-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (1-1).cert");
    }

    @Test
    public void verifyMscaUtoWorkshopCardSign12() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Workshop_Card_Sign (1-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (1-2).cert");
    }

    @Test
    public void verifyMscaUtoWorkshopCardSign21() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Workshop_Card_Sign (2-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (2-1).cert");
    }

    @Test
    public void verifyMscaUtoWorkshopCardSign22() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Workshop_Card_Sign (2-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (2-2).cert");
    }

    @Test
    public void verifyMscaUtoWorkshopCardSign31() {
        process("verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/Equipment/TC/UTO_Workshop_Card_Sign (3-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/UTO/UTO_MSCA_Card (3-1).cert");
    }
}
