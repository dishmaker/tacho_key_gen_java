package com.ults.jrc.tachograph.samples;

import static com.ults.jrc.tachograph.keytool.TachographKeyToolCli.process;

import org.junit.Test;

public class SamplesArcTest {

    @Test
    public void verifyMscaArc11() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (1-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert"
        );
    }

    @Test
    public void verifyMscaArc12() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (1-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert"
        );
    }

    @Test
    public void verifyMscaArc21() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (2-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (2).cert"
        );
    }

    @Test
    public void verifyMscaArc22() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (2-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (2).cert"
        );
    }

    @Test
    public void verifyMscaArc31() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (3-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (3).cert"
        );
    }

    @Test
    public void verifyMscaArcEgf11() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/EGF/ARC_EGF_MA (1-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_VU-EGF (1-1).cert");
    }

    @Test
    public void verifyMscaArcEgf12() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/EGF/ARC_EGF_MA (1-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_VU-EGF (1-2).cert");
    }

    @Test
    public void verifyMscaArcEgf21() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/EGF/ARC_EGF_MA (2-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_VU-EGF (2-1).cert");
    }

    @Test
    public void verifyMscaArcEgf22() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/EGF/ARC_EGF_MA (2-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_VU-EGF (2-2).cert");
    }

    @Test
    public void verifyMscaArcEgf31() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/EGF/ARC_EGF_MA (3-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_VU-EGF (3-1).cert");
    }

    @Test
    public void verifyMscaArcVuMa11() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/VU/ARC_VU_MA (1-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_VU-EGF (1-1).cert");
    }

    @Test
    public void verifyMscaArcVuMa12() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/VU/ARC_VU_MA (1-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_VU-EGF (1-2).cert");
    }

    @Test
    public void verifyMscaArcVuMa21() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/VU/ARC_VU_MA (2-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_VU-EGF (2-1).cert");
    }

    @Test
    public void verifyMscaArcVuMa22() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/VU/ARC_VU_MA (2-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_VU-EGF (2-2).cert");
    }

    @Test
    public void verifyMscaArcVuMa31() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/VU/ARC_VU_MA (3-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_VU-EGF (3-1).cert");
    }

    @Test
    public void verifyMscaArcVuSign11() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/VU/ARC_VU_Sign (1-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_VU-EGF (1-1).cert");
    }

    @Test
    public void verifyMscaArcVuSign12() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/VU/ARC_VU_Sign (1-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_VU-EGF (1-2).cert");
    }

    @Test
    public void verifyMscaArcVuSign21() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/VU/ARC_VU_Sign (2-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_VU-EGF (2-1).cert");
    }

    @Test
    public void verifyMscaArcVuSign22() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/VU/ARC_VU_Sign (2-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_VU-EGF (2-2).cert");
    }

    @Test
    public void verifyMscaArcVuSign31() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/VU/ARC_VU_Sign (3-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_VU-EGF (3-1).cert");
    }

    @Test
    public void verifyMscaArcCompanyCardMa11() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Company_Card_MA (1-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (1-1).cert");
    }

    @Test
    public void verifyMscaArcCompanyCardMa12() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Company_Card_MA (1-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (1-2).cert");
    }

    @Test
    public void verifyMscaArcCompanyCardMa21() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Company_Card_MA (2-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (2-1).cert");
    }

    @Test
    public void verifyMscaArcCompanyCardMa22() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Company_Card_MA (2-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (2-2).cert");
    }

    @Test
    public void verifyMscaArcCompanyCardMa31() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Company_Card_MA (3-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (3-1).cert");
    }

    @Test
    public void verifyMscaArcControlCardMa11() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Control_Card_MA (1-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (1-1).cert");
    }

    @Test
    public void verifyMscaArcControlCardMa12() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Control_Card_MA (1-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (1-2).cert");
    }

    @Test
    public void verifyMscaArcControlCardMa21() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Control_Card_MA (2-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (2-1).cert");
    }

    @Test
    public void verifyMscaArcControlCardMa22() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Control_Card_MA (2-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (2-2).cert");
    }

    @Test
    public void verifyMscaArcControlCardMa31() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Control_Card_MA (3-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (3-1).cert");
    }

    @Test
    public void verifyMscaArcDriverCardMa11() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Driver_Card_MA (1-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (1-1).cert");
    }

    @Test
    public void verifyMscaArcDriverCardMa12() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Driver_Card_MA (1-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (1-2).cert");
    }

    @Test
    public void verifyMscaArcDriverCardMa21() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Driver_Card_MA (2-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (2-1).cert");
    }

    @Test
    public void verifyMscaArcDriverCardMa22() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Driver_Card_MA (2-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (2-2).cert");
    }

    @Test
    public void verifyMscaArcDriverCardMa31() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Driver_Card_MA (3-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (3-1).cert");
    }

    @Test
    public void verifyMscaArcDriverCardSign11() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Driver_Card_Sign (1-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (1-1).cert");
    }

    @Test
    public void verifyMscaArcDriverCardSign12() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Driver_Card_Sign (1-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (1-2).cert");
    }

    @Test
    public void verifyMscaArcDriverCardSign21() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Driver_Card_Sign (2-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (2-1).cert");
    }

    @Test
    public void verifyMscaArcDriverCardSign22() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Driver_Card_Sign (2-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (2-2).cert");
    }

    @Test
    public void verifyMscaArcDriverCardSign31() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Driver_Card_Sign (3-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (3-1).cert");
    }

    @Test
    public void verifyMscaArcWorkshopCardMa11() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Workshop_Card_MA (1-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (1-1).cert");
    }

    @Test
    public void verifyMscaArcWorkshopCardMa12() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Workshop_Card_MA (1-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (1-2).cert");
    }

    @Test
    public void verifyMscaArcWorkshopCardMa21() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Workshop_Card_MA (2-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (2-1).cert");
    }

    @Test
    public void verifyMscaArcWorkshopCardMa22() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Workshop_Card_MA (2-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (2-2).cert");
    }

    @Test
    public void verifyMscaArcWorkshopCardMa31() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Workshop_Card_MA (3-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (3-1).cert");
    }

    @Test
    public void verifyMscaArcWorkshopCardSign11() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Workshop_Card_Sign (1-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (1-1).cert");
    }

    @Test
    public void verifyMscaArcWorkshopCardSign12() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Workshop_Card_Sign (1-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (1-2).cert");
    }

    @Test
    public void verifyMscaArcWorkshopCardSign21() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Workshop_Card_Sign (2-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (2-1).cert");
    }

    @Test
    public void verifyMscaArcWorkshopCardSign22() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Workshop_Card_Sign (2-2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (2-2).cert");
    }

    @Test
    public void verifyMscaArcWorkshopCardSign31() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Workshop_Card_Sign (3-1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (3-1).cert");
    }
}
