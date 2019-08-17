# Copyright 2019+ Maxim "Sheridan" Gorlov
# Distributed under the terms of the GNU General Public License v3

EAPI=6
EGIT_REPO_URI="https://github.com/Sheridan/${PN}"
inherit git-r3

DESCRIPTION="Exporting nftables metrics"
HOMEPAGE="https://github.com/Sheridan/nftables_exporter"
LICENSE="GPL-3"
SLOT="0"
RDEPEND="net-firewall/nftables"
DEPEND="dev-lang/go"

src_unpack() {
        git-r3_src_unpack
        cd "${S}"
        make get
}

src_compile() {
	make build
}

src_install() {
	newbin bin/${PN}-${PV} ${PN}
	dodoc "README.md"
        insinto /etc
	newins "${FILESDIR}/nftables_exporter.yaml" nftables_exporter.yaml
}
