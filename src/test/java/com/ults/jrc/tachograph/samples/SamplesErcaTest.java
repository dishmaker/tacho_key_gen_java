package com.ults.jrc.tachograph.samples;

import static com.ults.jrc.tachograph.keytool.TachographKeyToolCli.process;

import org.junit.Test;

public class SamplesErcaTest {

    @Test
    public void verifyErca1() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert");
    }

    @Test
    public void verifyErca12() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1) - ERCA (2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert");
    }

    @Test
    public void verifyErca2() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (2).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (2).cert");
    }

    @Test
    public void verifyErca23() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (2) - ERCA (3).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (2).cert");
    }

    @Test
    public void verifyErca3() {
        process(
                "verify",
                "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (3).cert",
                "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (3).cert");
    }
}
