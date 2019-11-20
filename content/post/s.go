package analyzerlib

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"bitbucket.org/scalock/aquatypes"
	"github.com/pkg/errors"
)

var (
	dockerVerRegex     = regexp.MustCompile(`\s*Version:\s*(.+)$`)
	dockerEditionRegex = regexp.MustCompile(`(-(c|e)e(?:-\d+)?)$`)
)

const (
	MINIMUM_REGEX_LEN = 4 // printable character sequences that are at least 4 characters long
	// While reading the content of executable, we crawl through each byte till we cross ascii range <32 & >126. once we cross the ascii range  then we check MINIMUM_REGEX_LEN
	//because, we need atleast 4 characters to apply the regex,
	//if number of characters found between ascii range 32to126 is < MINIMUM_REGEX_LEN then we dont want to apply regex over it.
	//if number of characters found between ascii range 32to126 is > MINIMUM_REGEX_LEN then we proceed to find regex pattern.

)

func isExecutableFile(info os.FileInfo) bool {
	return info.Mode()&0111 != 0 && info.Mode().IsRegular()
}

func (ctx *AnalyzerInput) checkExecutables(path string, info os.FileInfo) (files []interface{}, err error) {
	if isExecutableFile(info) {
		if ctx.isInstalledByPackageManager(path) {
			return files, nil
		}

		f, err := os.Open(path)
		if err != nil { //don't fail the scan
			ctx.log("Failed scanning executable file %s: %s", path, err)
			return files, nil
		}

		defer f.Close()

		name, version, cpe, err := getExecutableInfo(path, f)
		if err != nil { // don't fail the scan
			ctx.log("Failed getting info of executable %s: %s", path, err)
			return files, nil
		} else if name == "" {
			return files, nil
		}

		files = append(files, &aquatypes.ImageResource{
			Type:    aquatypes.ImageResourceType_EXECUTABLE,
			Path:    resourcePath(ctx.RootFolder, path, false),
			Name:    name,
			Cpe:     cpe,
			Version: version,
		})
	}
	return files, err
}

var (
	//	defaultRegExp                              = regexp.MustCompile(`[vV]ersion\s((\d+\.)+\d+(-p(\d+\.)*\d+)?)`)
	//	bashRegExp                                 = regexp.MustCompile(`/bash-([0-9\.]+)`)
	//	bashRegExp2                                = regexp.MustCompile(`(Bash version [1-9]\.[0-9])`)
	//	wgetRegExp                                 = regexp.MustCompile(`lib-O2-Wall\.(\d+\.\d+\?)`)
	//	zaRegExp                                   = regexp.MustCompile(`p7zip [Vv]ersion (\d+\.\d+)`)
	//	nodeRegExp                                 = regexp.MustCompile(`node [Vv](\d+\.\d+\.\d+)`)
	//	nodeRegExp2                                = regexp.MustCompile(`^node\.js/v[0-9]`)
	//	nodeJSRegExp                               = regexp.MustCompile(`node.js/[Vv](\d+\.\d+\.\d+)`)
	//	tomcatRegExp                               = regexp.MustCompile(`Apache Tomcat/([0-9\.]+)`)
	//	perlRegExp                                 = regexp.MustCompile(`/usr/lib/perl5/site_perl/([^/]+)/`)
	//	perlRegExp2                                = regexp.MustCompile(`^(v5\.[0-9]+)`)
	//	perlRegExp3                                = regexp.MustCompile(`^(libperl\.so\.[0-9])`)
	//	perlRegExp4                                = regexp.MustCompile(`^(perl5\.[0-9]+\.[0-9]+\.debug)`)
	//	perlivpRegExp                              = regexp.MustCompile(`# perlivp v([0-9][0-9]*(\.[0-9]+)+)`)
	//	javaRegExp                                 = regexp.MustCompile(`1.([4-9]).[0-9]+_([0-9]+)-b[0-9]+`)
	//	gdlibconfigRegExp                          = regexp.MustCompile(`echo ([0-9]+\.[0-9]+\.[0-9]+)`)
	//	fetchmailRegExp                            = regexp.MustCompile(`^([0-9]+\.[0-9]+\.[0-9]+)`)
	//	nanoRegExp                                 = regexp.MustCompile(`GNU nano ([0-9]+\.[0-9]+\.[0-9]+)`)
	//	rnanoRegExp                                = regexp.MustCompile(`GNU nano ([0-9]+\.[0-9]+\.[0-9]+)`)
	//	wiresharkRegExp                            = regexp.MustCompile(`^Version ([0-9]+\.[0-9]+\.[0-9]+)`)
	//	libxinesoRegExp                            = regexp.MustCompile(`^([0-9]+\.[0-9]+\.?[0-9]*\.?[0-9]*)$`)
	//	libMagickCoresoRegExp                      = regexp.MustCompile(`ImageMagick ([0-9\.-]+) `)
	//	librubysoRegExp                            = regexp.MustCompile(`^([0-9]+\.[0-9]+\.[0-9]+)$`)
	//	libflashplayersoRegExp                     = regexp.MustCompile(`FlashPlayer_([0-9]+)_([0-9]+)_([0-9]+)_([0-9]+)_FlashPlayer`)
	//	opensslRegExp                              = regexp.MustCompile(`OpenSSL ([0-9\.]+[a-z]*) `)
	//	opensslRegExp2                             = regexp.MustCompile(`^(OpenSSL [0-2]\.[0-9])`)
	//	gettextRegExp                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	envsubstRegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	msgcmpRegExp                               = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)`)
	//	msgfmtRegExp                               = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)`)
	//	msgmergeRegExp                             = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)`)
	//	msgunfmtRegExp                             = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)`)
	//	xgettextRegExp                             = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)`)
	//	msgattribRegExp                            = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)`)
	//	msgcommRegExp                              = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)`)
	//	msgconvRegExp                              = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)`)
	//	msgenRegExp                                = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)`)
	//	msgexecRegExp                              = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)`)
	//	msgfilterRegExp                            = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)`)
	//	msggrepRegExp                              = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)`)
	//	msginitRegExp                              = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)`)
	//	msguniqRegExp                              = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)`)
	//	syslogngRegExp                             = regexp.MustCompile(`^syslog-ng ([0-9\.]+)`)
	//	sarRegExp                                  = regexp.MustCompile(`.*sysstat-([0-9\.]+): sar.*`)
	//	bzip2RegExp                                = regexp.MustCompile(`.*bzip2-([0-9\.]+) source distribution.*`)
	//	cabextractRegExp                           = regexp.MustCompile(`^([0-9\.]+)$`)
	//	cpioRegExp                                 = regexp.MustCompile(`^([0-9]\.[0-9][0-9]*)`)
	//	gzipRegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	gunzipRegExp                               = regexp.MustCompile(`gunzip \(gzip\) ([0-9]\.[0-9][0-9]*)`)
	//	uncompressRegExp                           = regexp.MustCompile(`gunzip \(gzip\) ([0-9]\.[0-9][0-9]*)`)
	//	zcatRegExp                                 = regexp.MustCompile(`zcat \(gzip\) ([0-9]\.[0-9][0-9]*)`)
	//	gzexeRegExp                                = regexp.MustCompile(`gzexe \(gzip\) ([0-9]\.[0-9][0-9]*)`)
	//	zlessRegExp                                = regexp.MustCompile(`zless \(gzip\) ([0-9]\.[0-9][0-9]*)`)
	//	zmoreRegExp                                = regexp.MustCompile(`zmore \(gzip\) ([0-9]\.[0-9][0-9]*)`)
	//	znewRegExp                                 = regexp.MustCompile(`znew \(gzip\) ([0-9]\.[0-9][0-9]*)`)
	//	zcmpRegExp                                 = regexp.MustCompile(`zcmp \(gzip\) ([0-9]\.[0-9][0-9]*)`)
	//	zgrepRegExp                                = regexp.MustCompile(`zgrep \(gzip\) ([0-9]\.[0-9][0-9]*)`)
	//	zforceRegExp                               = regexp.MustCompile(`zforce \(gzip\) ([0-9]\.[0-9][0-9]*)`)
	//	zdiffRegExp                                = regexp.MustCompile(`z[^ ]* \(gzip\) ([0-9]\.[0-9][0-9]*)`)
	//	sharRegExp                                 = regexp.MustCompile(`^([0-9\.]+)$`)
	//	tarRegExp                                  = regexp.MustCompile(`tar \(GNU tar\) ([0-9]\.[0-9][0-9]*)`)
	//	tarRegExp2                                 = regexp.MustCompile(`^(1\.[1-9][0-9])`)
	//	rmtRegExp                                  = regexp.MustCompile(`rmt \(GNU tar\) ([0-9]\.[0-9][0-9]*)`)
	//	cdrdaoRegExp                               = regexp.MustCompile(`^([0-9\.]+)$`)
	//	mkisofsRegExp                              = regexp.MustCompile(`^([0-9\.]+)a([0-9\.]+)$`)
	//	gpgRegExp                                  = regexp.MustCompile(`Version: GnuPG v([0-9\.]+) `)
	//	gpgagentRegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	vimRegExp                                  = regexp.MustCompile(`VIM - Vi IMproved ([0-9\.]+) `)
	//	gsRegExp                                   = regexp.MustCompile(`ghostscript/([0-9\.]+)`)
	//	gocrRegExp                                 = regexp.MustCompile(`Optical Character Recognition --- gocr ([0-9\.]+) `)
	//	pdftopsRegExp                              = regexp.MustCompile(`^([0-9\.]+)$`)
	//	ncftpRegExp                                = regexp.MustCompile(`^.*NcFTP ([0-9\.]+)/([0-9]+) .*`)
	//	versionRegExp                              = regexp.MustCompile(`^Linux version ([0-9a-z.-]*) ([^@]*@[^)]*).*`)
	//	versionRegExp2                             = regexp.MustCompile(`^Linux version ([0-9a-z.-]*) \([^@]*@[^)]*\).*`)
	//	gimpRegExp                                 = regexp.MustCompile(`GIMP ([0-9]*\.[0-9]*\.[0-9]*)`)
	//	cdrdaoRegExp2                              = regexp.MustCompile(`^([0-9]\.[0-9\.]*)[^a-z]*$`)
	//	toc2cueRegExp                              = regexp.MustCompile(`^([0-9]\.[0-9\.]*)[^a-z]*$`)
	//	toc2cddbRegExp                             = regexp.MustCompile(`^([0-9]\.[0-9\.]*)[^a-z]*$`)
	//	isodebugRegExp                             = regexp.MustCompile(`^([0-9]\.[0-9\.]+)[^a-z]*$`)
	//	scgcheckRegExp                             = regexp.MustCompile(`^([0-9]\.[0-9\.]+)[^a-z]*$`)
	//	devdumpRegExp                              = regexp.MustCompile(`^([0-9]\.[0-9\.]+)[^a-z]*$`)
	//	isodumpRegExp                              = regexp.MustCompile(`^([0-9]\.[0-9\.]+)[^a-z]*$`)
	//	isovfyRegExp                               = regexp.MustCompile(`^([0-9]\.[0-9\.]+)[^a-z]*$`)
	//	kbxutilRegExp                              = regexp.MustCompile(`^([0-9]\.[0-9\.]+)[^a-zA-Z]*$`)
	//	watchgnupgRegExp                           = regexp.MustCompile(`watchgnupg \(GnuPG\) ([0-9]\.[0-9\.]+)[^a-zA-Z]*$`)
	//	gpgsmRegExp                                = regexp.MustCompile(`^([0-9]\.[0-9\.]+)[^a-zA-Z]*$`)
	//	gpgconfRegExp                              = regexp.MustCompile(`^([0-9]\.[0-9\.]+)[^a-zA-Z]*$`)
	//	pinentryRegExp                             = regexp.MustCompile(`^([0-9]\.[0-9\.]+)[^a-zA-Z]*$`)
	//	qemuRegExp                                 = regexp.MustCompile(`QEMU PC emulator version ([0-9]\.[0-9\.]+) .qemu.*`)
	//	eixRegExp                                  = regexp.MustCompile(`\(eix ([0-9]\.[0-9\.]+)\)`)
	//	eixRegExp2                                 = regexp.MustCompile(`eix ([0-9]\.[0-9\.]+) `)
	//	dvipngRegExp                               = regexp.MustCompile(`dvipng ([0-9]\.[0-9]+)`)
	//	dvigifRegExp                               = regexp.MustCompile(`dvipng ([0-9]\.[0-9]+)`)
	//	pdftoRegExp                                = regexp.MustCompile(`^([0-9]\.[0-9\.]+)[^a-zA-Z]*$`)
	//	aprRegExp                                  = regexp.MustCompile(`VERSION=.?([0-9]\.[0-9]\.[0-9]).?`)
	//	apuRegExp                                  = regexp.MustCompile(`VERSION=.?([0-9]\.[0-9]\.[0-9]+).?`)
	//	saslauthdRegExp                            = regexp.MustCompile(`^([0-9]\.[0-9]\.[0-9]+).*$`)
	//	bzcatRegExp                                = regexp.MustCompile(`   in the bzip2-([0-9][0-9]*(\.[0-9]+)+) source distribution.`)
	//	bunzip2RegExp                              = regexp.MustCompile(`   in the bzip2-([0-9][0-9]*(\.[0-9]+)+) source distribution.`)
	//	bzip2recoverRegExp                         = regexp.MustCompile(`bzip2recover ([0-9][0-9]*(\.[0-9]+)+): extracts blocks from damaged .bz2 files.`)
	//	libbz2soRegExp                             = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+). [0-9]*-.*`)
	//	unzipRegExp                                = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)`)
	//	isoinfoRegExp                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	isoinfoRegExp2                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	mkisofsRegExp2                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	mkisofsRegExp3                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	mkhybridRegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	mkhybridRegExp2                            = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	gpgconnectagentRegExp                      = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	symcryptrunRegExp                          = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	pdfinfoRegExp                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	pdfimagesRegExp                            = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	pdffontsRegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libpopplerRegExp                           = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libsqlite3RegExp                           = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libperlsoRegExp                            = regexp.MustCompile(`/usr/lib/perl5/([0-9][0-9]*(\.[0-9]+)+)/`)
	//	libperlsoRegExp2                           = regexp.MustCompile(`/usr/lib64/perl5/([0-9][0-9]*(\.[0-9]+)+)/`)
	//	libpythonRegExp                            = regexp.MustCompile(`^([0-9][0-9]*\.[0-9]+\.[0-9]+)`)
	//	libaprRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libaprutilRegExp                           = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libsasl2soRegExp                           = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libexpatsoRegExp                           = regexp.MustCompile(`expat_([0-9][0-9]*(\.[0-9]+)+)`)
	//	glibgettextizeRegExp                       = regexp.MustCompile(`version=([0-9][0-9]*(\.[0-9]+)+)`)
	//	gmimeuuRegExp                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	gmimeconfigRegExp                          = regexp.MustCompile(`echo ([0-9][0-9]*(\.[0-9]+)+)`)
	//	libcdioparanoiaRegExp                      = regexp.MustCompile(`libcdio ([0-9][0-9]*(\.[0-9]+)+) `)
	//	mmctoolRegExp                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	isoreadRegExp                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+) x86_64-pc-linux-gnu`)
	//	cdinfoRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+) x86_64-pc-linux-gnu`)
	//	isoinfoRegExp3                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+) x86_64-pc-linux-gnu`)
	//	cdreadRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	cddriveRegExp                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+) x86_64-pc-linux-gnu`)
	//	libcdiosoRegExp                            = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libsslsoRegExp                             = regexp.MustCompile(`OpenSSL ([0-9][0-9]*(\.[0-9]+)+[a-z]) [0-9]*`)
	//	libcryptosoRegExp                          = regexp.MustCompile(`OpenSSL ([0-9][0-9]*(\.[0-9]+)+[a-z]) [0-9]*`)
	//	unzzRegExp                                 = regexp.MustCompile(`version zziplib ([0-9][0-9]*(\.[0-9]+)+)`)
	//	zzRegExp                                   = regexp.MustCompile(`version zziplib ([0-9][0-9]*(\.[0-9]+)+)`)
	//	straceRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	gitRegExp                                  = regexp.MustCompile(`^([1-3][0-9]*(\.[0-9]+)+)`)
	//	svnRegExp                                  = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libsvnRegExp                               = regexp.MustCompile(`SVN/([0-9][0-9]*(\.[0-9]+)+) \(r`)
	//	libkdeRegExp                               = regexp.MustCompile(`\(KDE ([0-9][0-9]*(\.[0-9]+)+)\)`)
	//	muttRegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	exiv2RegExp                                = regexp.MustCompile(`exiv2 ([0-9][0-9]*(\.[0-9]+)+)`)
	//	exiv2RegExp2                               = regexp.MustCompile(`exiv2 ([0-9][0-9]*(\.[0-9]+)+)`)
	//	libasoundsoRegExp                          = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libFLACsoRegExp                            = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libgstRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libpngRegExp                               = regexp.MustCompile(`version=.([0-9][0-9]*(\.[0-9]+)+).`)
	//	libpngRegExp2                              = regexp.MustCompile(`version=.([0-9][0-9]*(\.[0-9]+)+).`)
	//	libpngRegExp3                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libpngRegExp4                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libsndfilesoRegExp                         = regexp.MustCompile(`libsndfile-([0-9][0-9]*(\.[0-9]+)+)`)
	//	libsndfilesoRegExp2                        = regexp.MustCompile(`libsndfile-([0-9][0-9]*(\.[0-9]+)+)`)
	//	zipRegExp                                  = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	rviRegExp                                  = regexp.MustCompile(`Gentoo-([0-9][0-9]*(\.[0-9]+)+)`)
	//	vimRegExp2                                 = regexp.MustCompile(`Gentoo-([0-9][0-9]*(\.[0-9]+)+)`)
	//	dbusbindingtoolRegExp                      = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	gmimeconfigRegExp2                         = regexp.MustCompile(`echo ([0-9][0-9]*(\.[0-9]+)+)`)
	//	xml2configRegExp                           = regexp.MustCompile(`echo ([0-9][0-9]*(\.[0-9]+)+)`)
	//	xsltconfigRegExp                           = regexp.MustCompile(`echo ([0-9][0-9]*(\.[0-9]+)+)`)
	//	libxsltso1126RegExp                        = regexp.MustCompile(`LIBXML2_([0-9][0-9]*(\.[0-9]+)+)`)
	//	unzipmemRegExp                             = regexp.MustCompile(`../../bins/unzip-mem.c version zziplib ([0-9][0-9]*(\.[0-9]+)+)`)
	//	libMagickCoresoRegExp2                     = regexp.MustCompile(`file:///usr/share/doc/imagemagick-([0-9][0-9]*(\.[0-9]+)+)/index.html`)
	//	libMagickCoresoRegExp3                     = regexp.MustCompile(`file:///usr/share/doc/imagemagick-([0-9][0-9]*(\.[0-9]+)+)/index.html`)
	//	libvorbissoRegExp                          = regexp.MustCompile(`Xiph.Org libVorbis ([0-9][0-9]*(\.[0-9]+)+)`)
	//	libvorbissoRegExp2                         = regexp.MustCompile(`Xiph.Org libVorbis ([0-9][0-9]*(\.[0-9]+)+)`)
	//	libvorbissoRegExp3                         = regexp.MustCompile(`Xiph.Org libVorbis ([0-9][0-9]*(\.[0-9]+)+)`)
	//	swrast_drisoRegExp                         = regexp.MustCompile(`%u.%u Mesa ([0-9][0-9]*(\.[0-9]+)+)`)
	//	libt1so512RegExp                           = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)`)
	//	xinelistRegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	xineplug_inp_RegExp                        = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libxinesoRegExp2                           = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libxvidcoresoRegExp                        = regexp.MustCompile(`@xvid-([0-9][0-9]*(\.[0-9]+)+)`)
	//	vobStreamerRegExp                          = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	testOnDemandRTSPServerRegExp               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	testMPEG1or2SplitterRegExp                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	testMPEG4VideoToDarwinRegExp               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	MPEG2TransportStreamIndexerRegExp          = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	testMPEG4VideoStreamerRegExp               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	testMPEG2TransportStreamTrickPlayRegExp    = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	testMPEG1or2AudioVideoToDarwinRegExp       = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	testMPEG1or2ProgramToTransportStreamRegExp = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	testWAVAudioStreamerRegExp                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	openRTSPRegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	playSIPRegExp                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	testAMRAudioStreamerRegExp                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libliveMediasoRegExp                       = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	iptablesRegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libirc_proxysoRegExp                       = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	dhcpcdRegExp                               = regexp.MustCompile(`dhcpcd ([0-9][0-9]*(\.[0-9]+)+) starting`)
	//	vncviewerRegExp                            = regexp.MustCompile(`TightVNC Viewer version ([0-9][0-9]*(\.[0-9]+)+)`)
	//	XvncRegExp                                 = regexp.MustCompile(`TightVNC-([0-9][0-9]*(\.[0-9]+)+)`)
	//	wgetRegExp2                                = regexp.MustCompile(`^([0-2][0-9]*(\.[0-9]+)+)`)
	//	wgetRegExp3                                = regexp.MustCompile(`Wall.*(\d+\.\d+)`)
	//	panRegExp                                  = regexp.MustCompile(`pan ([0-9][0-9]*(\.[0-9]+)+)`)
	//	cupsdRegExp                                = regexp.MustCompile(`# Subscription configuration file for CUPS v([0-9][0-9]*(\.[0-9]+)+)`)
	//	printerscgiRegExp                          = regexp.MustCompile(`CUPS v([0-9][0-9]*(\.[0-9]+)+)`)
	//	jobscgiRegExp                              = regexp.MustCompile(`CUPS v([0-9][0-9]*(\.[0-9]+)+)`)
	//	classescgiRegExp                           = regexp.MustCompile(`CUPS v([0-9][0-9]*(\.[0-9]+)+)`)
	//	helpcgiRegExp                              = regexp.MustCompile(`CUPS v([0-9][0-9]*(\.[0-9]+)+)`)
	//	admincgiRegExp                             = regexp.MustCompile(`CUPS v([0-9][0-9]*(\.[0-9]+)+)`)
	//	libcupssoRegExp                            = regexp.MustCompile(`CUPS/([0-9][0-9]*(\.[0-9]+)+)`)
	//	libcupssoRegExp2                           = regexp.MustCompile(`CUPS/([0-9][0-9]*(\.[0-9]+)+)`)
	//	wpa_RegExp                                 = regexp.MustCompile(`wpa_.* v([0-9][0-9]*(\.[0-9]+)+)`)
	//	setfaclRegExp                              = regexp.MustCompile(`%s ([0-9][0-9]*(\.[0-9]+)+)`)
	//	getfaclRegExp                              = regexp.MustCompile(`%s ([0-9][0-9]*(\.[0-9]+)+)`)
	//	busyboxRegExp                              = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+) 20[0-9]+-[0-9]+-[0-9]+`)
	//	busyboxRegExp2                             = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+) 20[0-9]+-[0-9]+-[0-9]+`)
	//	busyboxRegExp3                             = regexp.MustCompile(`^BusyBox v[0-9]\.[0-9]+\.[0-9]+ \(.`)
	//	bbRegExp                                   = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+) 20[0-9]+-[0-9]+-[0-9]+`)
	//	bbRegExp2                                  = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+) 20[0-9]+-[0-9]+-[0-9]+`)
	//	mdevRegExp                                 = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+) 20[0-9]+-[0-9]+-[0-9]+`)
	//	mdevRegExp2                                = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+) 20[0-9]+-[0-9]+-[0-9]+`)
	//	dbusRegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	dbusRegExp2                                = regexp.MustCompile(`D-Bus ([0-9][0-9]*(\.[0-9]+)+)`)
	//	libdbusRegExp                              = regexp.MustCompile(`D-Bus ([0-9][0-9]*(\.[0-9]+)+)`)
	//	edRegExp                                   = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	redRegExp                                  = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	ejectRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	findRegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	oldfindRegExp                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	xargsRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	grodviRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	grolj4RegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	grottyRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	grolbpRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	groffRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	sandboxRegExp                              = regexp.MustCompile(`../../sandbox-([0-9][0-9]*(\.[0-9]+)+)/libsbutil/src/string.c`)
	//	libsandboxsoRegExp                         = regexp.MustCompile(`../../sandbox-([0-9][0-9]*(\.[0-9]+)+)/libsbutil/src/debug.c`)
	//	texindexRegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	installinfoRegExp                          = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	infokeyRegExp                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	infoRegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	tunelpRegExp                               = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	tunelpRegExp2                              = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	fdformatRegExp                             = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	fdformatRegExp2                            = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	rtcwakeRegExp                              = regexp.MustCompile(`rtcwake from util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	rtcwakeRegExp2                             = regexp.MustCompile(`rtcwake from util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	readprofileRegExp                          = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	readprofileRegExp2                         = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	ldattachRegExp                             = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	ldattachRegExp2                            = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	isosizeRegExp                              = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	isosizeRegExp2                             = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	calRegExp                                  = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	calRegExp2                                 = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	renameRegExp                               = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	renameRegExp2                              = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	chrtRegExp                                 = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	chrtRegExp2                                = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	tasksetRegExp                              = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	tasksetRegExp2                             = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	ddateRegExp                                = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	ddateRegExp2                               = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	flockRegExp                                = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	flockRegExp2                               = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	scriptRegExp                               = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	scriptRegExp2                              = regexp.MustCompile(`^util-linux ([0-9][0-9]*(\.[0-9]+)+)`)
	//	reniceRegExp                               = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	reniceRegExp2                              = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	fdiskRegExp                                = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	fdiskRegExp2                               = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	fsckminixRegExp                            = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	fsckminixRegExp2                           = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	mkfsRegExp                                 = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	mkfsRegExp2                                = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	fsckRegExp                                 = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	fsckRegExp2                                = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	sfdiskRegExp                               = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	sfdiskRegExp2                              = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	blkidRegExp                                = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	blkidRegExp2                               = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	mkswapRegExp                               = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	mkswapRegExp2                              = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	mkfsminixRegExp                            = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	mkfsminixRegExp2                           = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	blockdevRegExp                             = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	blockdevRegExp2                            = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	swapoffRegExp                              = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	swapoffRegExp2                             = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	mkfsbfsRegExp                              = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	mkfsbfsRegExp2                             = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	mkfscramfsRegExp                           = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	mkfscramfsRegExp2                          = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	cfdiskRegExp                               = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	cfdiskRegExp2                              = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	hwclockRegExp                              = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	hwclockRegExp2                             = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	swaponRegExp                               = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	swaponRegExp2                              = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	switch_rootRegExp                          = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	switch_rootRegExp2                         = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	grubinstallRegExp                          = regexp.MustCompile(`VERSION=([0-9][0-9]*(\.[0-9]+)+)`)
	//	grubsetdefaultRegExp                       = regexp.MustCompile(`VERSION=([0-9][0-9]*(\.[0-9]+)+)`)
	//	grubterminfoRegExp                         = regexp.MustCompile(`VERSION=([0-9][0-9]*(\.[0-9]+)+)`)
	//	grubRegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	asRegExp                                   = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)`)
	//	libbfdsoRegExp                             = regexp.MustCompile(`/usr/lib64/binutils/x86_64-pc-linux-gnu/([0-9][0-9]*(\.[0-9]+)+)/debug`)
	//	libopcodesRegExp                           = regexp.MustCompile(`libopcodes-([0-9][0-9]*(\.[0-9]+)+)\.[0-9]+.so`)
	//	libbfdRegExp                               = regexp.MustCompile(`/usr/lib64/binutils/x86_64-pc-linux-gnu/([0-9][0-9]*(\.[0-9]+)+)/debug`)
	//	libbfdRegExp2                              = regexp.MustCompile(`/usr/lib/binutils/x86_64-pc-linux-gnu/([0-9][0-9]*(\.[0-9]+)+)/debug`)
	//	lexRegExp                                  = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	lexRegExp2                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	flexRegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	flexRegExp2                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	protoizeRegExp                             = regexp.MustCompile(`/usr/lib/gcc/[^/]*/([0-9][0-9]*(\.[0-9]+)+)/include`)
	//	protoizeRegExp2                            = regexp.MustCompile(`/usr/lib/gcc/[^/]*/([0-9][0-9]*(\.[0-9]+)+)/include`)
	//	unprotoizeRegExp                           = regexp.MustCompile(`/usr/lib/gcc/[^/]*/([0-9][0-9]*(\.[0-9]+)+)/include`)
	//	unprotoizeRegExp2                          = regexp.MustCompile(`/usr/lib/gcc/[^/]*/([0-9][0-9]*(\.[0-9]+)+)/include`)
	//	gdbserverRegExp                            = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	gettextshRegExp                            = regexp.MustCompile(`      version=([0-9][0-9]*(\.[0-9]+)+)`)
	//	msgcatRegExp                               = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)`)
	//	ngettextRegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	gettextizeRegExp                           = regexp.MustCompile(`version=([0-9][0-9]*(\.[0-9]+)+)`)
	//	libgettextRegExp                           = regexp.MustCompile(`libgettext.*-([0-9][0-9]*(\.[0-9]+)+).so`)
	//	m4RegExp                                   = regexp.MustCompile(`GNU M4 ([0-9][0-9]*(\.[0-9]+)+)`)
	//	makeRegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	gmakeRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	lsattrRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	chattrRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libext2fssoRegExp                          = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	fsckext2RegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	e2fsckRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	fsckext4devRegExp                          = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	e2imageRegExp                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	mkfsext3RegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	mke2fsRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	e2labelRegExp                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	dumpe2fsRegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	fsckext4RegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	tune2fsRegExp                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	debugfsRegExp                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	mkfsext2RegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	fsckext3RegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	mkfsext4devRegExp                          = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	mkfsext4RegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	resize2fsRegExp                            = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libext2fssoRegExp2                         = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libfusesoRegExp                            = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	iconvconfigRegExp                          = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	rpcinfoRegExp                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	nscdRegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	lddlibc4RegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	iconvRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	localeRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	rpcgenRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	getconfRegExp                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	getentRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	localedefRegExp                            = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	sprofRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libthread_dbRegExp                         = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	ldconfigRegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libpthreadsoRegExp                         = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libpthreadRegExp                           = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	gencatRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	pcprofiledumpRegExp                        = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	slnRegExp                                  = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)`)
	//	pam_cracklibsoRegExp                       = regexp.MustCompile(`LIBPAM_EXTENSION_([0-9][0-9]*(\.[0-9]+)+)`)
	//	pam_xauthsoRegExp                          = regexp.MustCompile(`LIBPAM_MODUTIL_([0-9][0-9]*(\.[0-9]+)+)`)
	//	libzsoRegExp                               = regexp.MustCompile(` inflate ([0-9][0-9]*(\.[0-9]+)+) Copyright`)
	//	pangoRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libpangoRegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	xscreensaverRegExp                         = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	id3v2RegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libid3RegExp                               = regexp.MustCompile(`id3lib-([0-9][0-9]*(\.[0-9]+)+)`)
	//	id3infoRegExp                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	id3cpRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	neonconfigRegExp                           = regexp.MustCompile(`echo neon ([0-9][0-9]*(\.[0-9]+)+)`)
	//	transmissionRegExp                         = regexp.MustCompile(`Transmission ([0-9][0-9]*(\.[0-9]+)+)`)
	//	acpiRegExp                                 = regexp.MustCompile(`acpid-([0-9][0-9]*(\.[0-9]+)+)`)
	//	libbrlttyRegExp                            = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)@`)
	//	catRegExp                                  = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	chgrpRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	chmodRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	chownRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	cpRegExp                                   = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	dateRegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	ddRegExp                                   = regexp.MustCompile(`A([0-9][0-9]*(\.[0-9]+)+)`)
	//	dirRegExp                                  = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	echoRegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	falseRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	lnRegExp                                   = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	lsRegExp                                   = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	mkdirRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	mknodRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	mvRegExp                                   = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	pwdRegExp                                  = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	readlinkRegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	rmRegExp                                   = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	rmdirRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	vdirRegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	syncRegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	touchRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	trueRegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	unameRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	mktempRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	installRegExp                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	hostidRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	niceRegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	whoRegExp                                  = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	usersRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	pinkyRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	chconRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	dircolorsRegExp                            = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	duRegExp                                   = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	linkRegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	mkfifoRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	nohupRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	shredRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	statRegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	unlinkRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	cksumRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	commRegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	csplitRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	cutRegExp                                  = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	expandRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	fmtRegExp                                  = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	foldRegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	headRegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	joinRegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	groupsRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	md5sumRegExp                               = regexp.MustCompile(`0123456789abcdef([0-9][0-9]*(\.[0-9]+)+)`)
	//	nlRegExp                                   = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	odRegExp                                   = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	pasteRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	prRegExp                                   = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	ptxRegExp                                  = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	sha1sumRegExp                              = regexp.MustCompile(`0123456789abcdef([0-9][0-9]*(\.[0-9]+)+)`)
	//	sha224sumRegExp                            = regexp.MustCompile(`0123456789abcdef([0-9][0-9]*(\.[0-9]+)+)`)
	//	sha256sumRegExp                            = regexp.MustCompile(`0123456789abcdef([0-9][0-9]*(\.[0-9]+)+)`)
	//	sha384sumRegExp                            = regexp.MustCompile(`0123456789abcdef([0-9][0-9]*(\.[0-9]+)+)`)
	//	sha512sumRegExp                            = regexp.MustCompile(`0123456789abcdef([0-9][0-9]*(\.[0-9]+)+)`)
	//	shufRegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	splitRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	tacRegExp                                  = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	tailRegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	trRegExp                                   = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	tsortRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	unexpandRegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	uniqRegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	wcRegExp                                   = regexp.MustCompile(`dA([0-9][0-9]*(\.[0-9]+)+)`)
	//	basenameRegExp                             = regexp.MustCompile(`^([0-46-9][0-9]*(\.[0-9]+)+)`)
	//	envRegExp                                  = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	exprRegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	factorRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	idRegExp                                   = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	lognameRegExp                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	pathchkRegExp                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	printenvRegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	printfRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	runconRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	teeRegExp                                  = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	truncateRegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	ttyRegExp                                  = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	whoamiRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	yesRegExp                                  = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	base64RegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	archRegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	chrootRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	touchRegExp2                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	mtgnuRegExp                                = regexp.MustCompile(`GNU cpio ([0-9][0-9]*(\.[0-9]+)+)`)
	//	libevolutionRegExp                         = regexp.MustCompile(`Evolution ([0-9][0-9]*(\.[0-9]+)+) `)
	//	evolutionRegExp                            = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	gdbRegExp                                  = regexp.MustCompile(`^([0-9][0-9]*\.[0-9]+(\.[0-9]+)+)`)
	//	gdmbinaryRegExp                            = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	gdmflexiserverRegExp                       = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	gpgsplitRegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	gpgzipRegExp                               = regexp.MustCompile(`VERSION=([0-9][0-9]*(\.[0-9]+)+)`)
	//	hpmkuriRegExp                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	iptablesRegExp2                            = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	ip6tablesRegExp                            = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	ip6tablesrestoreRegExp                     = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	ip6tablessaveRegExp                        = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	lftpRegExp                                 = regexp.MustCompile(`lftp/([0-9][0-9]*(\.[0-9]+)+)`)
	//	ltraceRegExp                               = regexp.MustCompile(`ltrace version ([0-9][0-9]*(\.[0-9]+)+).`)
	//	libaudioscrobblersoRegExp                  = regexp.MustCompile(`Rhythmbox/([0-9][0-9]*(\.[0-9]+)+)`)
	//	libdaapsoRegExp                            = regexp.MustCompile(`Rhythmbox ([0-9][0-9]*(\.[0-9]+)+)`)
	//	libmtpdevicesoRegExp                       = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libfmradiosoRegExp                         = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	rhythmboxRegExp                            = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	rsyncRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	imuxsocksoRegExp                           = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	imuxsocksoRegExp2                          = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	ommailsoRegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	ommailsoRegExp2                            = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	sudoRegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+(p[0-9]*)?)`)
	//	visudoRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+(p[0-9]*)?)`)
	//	vinagreRegExp                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	w3mRegExp                                  = regexp.MustCompile(`w3m/([0-9][0-9]*(\.[0-9]+)+)`)
	//	xinputRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	xsaneRegExp                                = regexp.MustCompile(`xsane-([0-9][0-9]*(\.[0-9]+)+)`)
	//	xmlRegExp                                  = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	xmlstarletRegExp                           = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	ndisasmRegExp                              = regexp.MustCompile(`NASM ([0-9][0-9]*(\.[0-9]+)+)`)
	//	ndisasmRegExp2                             = regexp.MustCompile(`NASM ([0-9][0-9]*(\.[0-9]+)+)`)
	//	cddriveRegExp2                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+) `)
	//	cdinfoRegExp2                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+) `)
	//	isoinfoRegExp4                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+) `)
	//	isoreadRegExp2                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+) `)
	//	libtasn1soRegExp                           = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	asn1RegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libgconf2soRegExp                          = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	gconftool2RegExp                           = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	gdmRegExp                                  = regexp.MustCompile(`GDM ([0-9][0-9]*(\.[0-9]+)+)`)
	//	libgtop20soRegExp                          = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libgtop20soRegExp2                         = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	formailRegExp                              = regexp.MustCompile(` v([0-9][0-9]*(\.[0-9]+)+) 20`)
	//	postaliasRegExp                            = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	postcatRegExp                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	postfixRegExp                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	postfixRegExp2                             = regexp.MustCompile(`^(mail_version=[0-9]+)`)
	//	postkickRegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	postlogRegExp                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	postmapRegExp                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	postmultiRegExp                            = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	postsuperRegExp                            = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	postdropRegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	postqueueRegExp                            = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	faadRegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	imlib2configRegExp                         = regexp.MustCompile(`echo ([0-9][0-9]*(\.[0-9]+)+)`)
	//	xineRegExp                                 = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	fbxineRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	nfsstatRegExp                              = regexp.MustCompile(`nfsstat: ([0-9][0-9]*(\.[0-9]+)+)`)
	//	rpcmountdRegExp                            = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	showmountRegExp                            = regexp.MustCompile(`showmount for ([0-9][0-9]*(\.[0-9]+)+)`)
	//	rpcstatdRegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	irssiRegExp                                = regexp.MustCompile(`irssi ([0-9][0-9]*(\.[0-9]+)+)`)
	//	aptRegExp                                  = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	aptRegExp2                                 = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	idljRegExp                                 = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	idljRegExp2                                = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	keytoolRegExp                              = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	keytoolRegExp2                             = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	jarsignerRegExp                            = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	jarsignerRegExp2                           = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	policytoolRegExp                           = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	policytoolRegExp2                          = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	jarRegExp                                  = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	jarRegExp2                                 = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	xjcRegExp                                  = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	xjcRegExp2                                 = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	schemagenRegExp                            = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	schemagenRegExp2                           = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	wsgenRegExp                                = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	wsgenRegExp2                               = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	wsimportRegExp                             = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	wsimportRegExp2                            = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	appletviewerRegExp                         = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	appletviewerRegExp2                        = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	rmicRegExp                                 = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	rmicRegExp2                                = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	rmiregistryRegExp                          = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	rmiregistryRegExp2                         = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	rmidRegExp                                 = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	rmidRegExp2                                = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	native2asciiRegExp                         = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	native2asciiRegExp2                        = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	serialverRegExp                            = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	serialverRegExp2                           = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	jpsRegExp                                  = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	jpsRegExp2                                 = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	jstatRegExp                                = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	jstatRegExp2                               = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	jstatdRegExp                               = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	jstatdRegExp2                              = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	jsadebugdRegExp                            = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	jsadebugdRegExp2                           = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	jstackRegExp                               = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	jstackRegExp2                              = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	jmapRegExp                                 = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	jmapRegExp2                                = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	jinfoRegExp                                = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	jinfoRegExp2                               = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	jconsoleRegExp                             = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	jconsoleRegExp2                            = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	jrunscriptRegExp                           = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	jrunscriptRegExp2                          = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	jhatRegExp                                 = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	jhatRegExp2                                = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	tnameservRegExp                            = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	tnameservRegExp2                           = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	orbdRegExp                                 = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	orbdRegExp2                                = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	servertoolRegExp                           = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	servertoolRegExp2                          = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	pack200RegExp                              = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	pack200RegExp2                             = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	extcheckRegExp                             = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	extcheckRegExp2                            = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	jdbRegExp                                  = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	jdbRegExp2                                 = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	keytoolRegExp3                             = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	keytoolRegExp4                             = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	policytoolRegExp3                          = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	policytoolRegExp4                          = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	rmiregistryRegExp3                         = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	rmiregistryRegExp4                         = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	rmidRegExp3                                = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	rmidRegExp4                                = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	tnameservRegExp3                           = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	tnameservRegExp4                           = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	orbdRegExp3                                = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	orbdRegExp4                                = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	servertoolRegExp3                          = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	servertoolRegExp4                          = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	pack200RegExp3                             = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	pack200RegExp4                             = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	java_vmRegExp                              = regexp.MustCompile(`JAVA_PLUGIN_VERSION=([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	java_vmRegExp2                             = regexp.MustCompile(`JAVA_PLUGIN_VERSION=([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	libjavasoRegExp                            = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	libjavasoRegExp2                           = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	libjavaplugin_nscp_gcc29soRegExp           = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	libjavaplugin_nscp_gcc29soRegExp2          = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`)
	//	mod_sslsoRegExp                            = regexp.MustCompile(`mod_ssl/([0-9][0-9]*(\.[0-9]+)+)`)
	//	xinputRegExp2                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libvirtdRegExp                             = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)`)
	//	libvirtsoRegExp                            = regexp.MustCompile(`LIBVIRT_PRIVATE_([0-9][0-9]*(\.[0-9]+)+)`)
	//	libvirtqemusoRegExp                        = regexp.MustCompile(`LIBVIRT_PRIVATE_([0-9][0-9]*(\.[0-9]+)+)`)
	//	dnsmasqRegExp                              = regexp.MustCompile(`dnsmasq-([0-9][0-9]*(\.[0-9]+)+)`)
	//	gnutlsRegExp                               = regexp.MustCompile(`GnuTLS ([0-9][0-9]*(\.[0-9]+)+)`)
	//	psktoolRegExp                              = regexp.MustCompile(`GnuTLS ([0-9][0-9]*(\.[0-9]+)+)`)
	//	srptoolRegExp                              = regexp.MustCompile(`GnuTLS ([0-9][0-9]*(\.[0-9]+)+)`)
	//	certtoolRegExp                             = regexp.MustCompile(`GnuTLS ([0-9][0-9]*(\.[0-9]+)+)`)
	//	libgnutlsextrasoRegExp                     = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libgnutlssoRegExp                          = regexp.MustCompile(`Version: OpenPrivacy ([0-9][0-9]*(\.[0-9]+)+)%s`)
	//	makeinfoRegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libtoolRegExp                              = regexp.MustCompile(`VERSION=([0-9][0-9]*(\.[0-9]+)+)`)
	//	linksRegExp                                = regexp.MustCompile(`gif2png ([0-9][0-9]*(\.[0-9]+)+)`)
	//	linksRegExp2                               = regexp.MustCompile(`gif2png ([0-9][0-9]*(\.[0-9]+)+)`)
	//	_cairosoRegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	resolve_stack_dumpRegExp                   = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	mysqlRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libphp5soRegExp                            = regexp.MustCompile(`PHP/([0-9][0-9]*(\.[0-9]+)+)-pl0-gentoo`)
	//	phpRegExp                                  = regexp.MustCompile(`^X-Powered-By: PHP/([0-9][0-9]*)`)
	//	libmcryptsoRegExp                          = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libmountsoRegExp                           = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+).0`)
	//	libblkidsoRegExp                           = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+).0`)
	//	umountRegExp                               = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	mountRegExp                                = regexp.MustCompile(`util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`)
	//	findmntRegExp                              = regexp.MustCompile(`MOUNT_([0-9][0-9]*(\.[0-9]+)+)`)
	//	aureportRegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	ausearchRegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	auditdRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	auditctlRegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libmysqlclient_rsoRegExp                   = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)`)
	//	libmysqlclientsoRegExp                     = regexp.MustCompile(`([0-9][0-9]*(\.[0-9]+)+)`)
	//	bsdcpioRegExp                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	bsdtarRegExp                               = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libarchivesoRegExp                         = regexp.MustCompile(`libarchive ([0-9][0-9]*(\.[0-9]+)+)`)
	//	namedRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libiscsoRegExp                             = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libisccfgsoRegExp                          = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	libbind9soRegExp                           = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	liblwressoRegExp                           = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	courierimapdRegExp                         = regexp.MustCompile(`Courier-IMAP ([0-9][0-9]*(\.[0-9]+)+)/.*`)
	//	newroleRegExp                              = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	seconRegExp                                = regexp.MustCompile(`^([0-9][0-9]*(\.[0-9]+)+)`)
	//	lighttpdRegExp                             = regexp.MustCompile(`Server: lighttpd/([0-9][0-9]*(\.[0-9]+)+)`)
	//	lighttpdRegExp2                            = regexp.MustCompile(`^(lighttpd/[1-2]\.[0-9]+\.[0-9]+)$`)
	//	moddirlistingsoRegExp                      = regexp.MustCompile(`lighttpd/([0-9][0-9]*(\.[0-9]+)+)`)
	//	mod_cgisoRegExp                            = regexp.MustCompile(`lighttpd/([0-9][0-9]*(\.[0-9]+)+)`)
	//	mod_scgisoRegExp                           = regexp.MustCompile(`lighttpd/([0-9][0-9]*(\.[0-9]+)+)`)
	//	mod_fastcgisoRegExp                        = regexp.MustCompile(`lighttpd/([0-9][0-9]*(\.[0-9]+)+)`)
	//	mod_ssisoRegExp                            = regexp.MustCompile(`lighttpd/([0-9][0-9]*(\.[0-9]+)+)`)
	//	javaJDKRegExp                              = regexp.MustCompile(`^1[0-9]\.[0-9]\.[0-9]\+[0-9]+`)
	//	javaRegOSExp                               = regexp.MustCompile(`^(1\.[4-9]\.[0-9]+_([0-9]+))`)
	//	mysqlmariaRegExp                           = regexp.MustCompile(`^(1[0-2]\.[0-9]+\.[0-9]+-MariaDB$)`)

	//defaultRegExp                              = `[vV]ersion\s((\d+\.)+\d+(-p(\d+\.)*\d+)?)`
	//bashRegExp                                 = `/bash-([0-9\.]+)`
	//wgetRegExp                                 = `lib-O2-Wall\.(\d+\.\d+\?)`
	//zaRegExp                                   = `p7zip [Vv]ersion (\d+\.\d+)`
	//nodeRegExp                                 = `node [Vv](\d+\.\d+\.\d+)`
	//tomcatRegExp                               = `Apache Tomcat/([0-9\.]+)`
	//perlRegExp                                 = `/usr/lib/perl5/site_perl/([^/]+)/`
	//perlivpRegExp                              = `# perlivp v([0-9][0-9]*(\.[0-9]+)+)`
	//javaRegExp                                 = `1.([4-9]).[0-9]+_([0-9]+)-b[0-9]+`
	//gdlibconfigRegExp                          = `echo ([0-9]+\.[0-9]+\.[0-9]+)`
	//fetchmailRegExp                            = `^([0-9]+\.[0-9]+\.[0-9]+)`
	//nanoRegExp                                 = `GNU nano ([0-9]+\.[0-9]+\.[0-9]+)`
	//rnanoRegExp                                = `GNU nano ([0-9]+\.[0-9]+\.[0-9]+)`
	//wiresharkRegExp                            = `^Version ([0-9]+\.[0-9]+\.[0-9]+)`
	//libxinesoRegExp                            = `^([0-9]+\.[0-9]+\.?[0-9]*\.?[0-9]*)$`
	//libMagickCoresoRegExp                      = `ImageMagick ([0-9\.-]+) `
	//librubysoRegExp                            = `^([0-9]+\.[0-9]+\.[0-9]+)$`
	//libflashplayersoRegExp                     = `FlashPlayer_([0-9]+)_([0-9]+)_([0-9]+)_([0-9]+)_FlashPlayer`
	//opensslRegExp                              = `OpenSSL ([0-9\.]+[a-z]*) `
	//gettextRegExp                              = `^([0-9][0-9]*(\.[0-9]+)+)`
	//envsubstRegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//msgcmpRegExp                               = `([0-9][0-9]*(\.[0-9]+)+)`
	//msgfmtRegExp                               = `([0-9][0-9]*(\.[0-9]+)+)`
	//msgmergeRegExp                             = `([0-9][0-9]*(\.[0-9]+)+)`
	//msgunfmtRegExp                             = `([0-9][0-9]*(\.[0-9]+)+)`
	//xgettextRegExp                             = `([0-9][0-9]*(\.[0-9]+)+)`
	//msgattribRegExp                            = `([0-9][0-9]*(\.[0-9]+)+)`
	//msgcommRegExp                              = `([0-9][0-9]*(\.[0-9]+)+)`
	//msgconvRegExp                              = `([0-9][0-9]*(\.[0-9]+)+)`
	//msgenRegExp                                = `([0-9][0-9]*(\.[0-9]+)+)`
	//msgexecRegExp                              = `([0-9][0-9]*(\.[0-9]+)+)`
	//msgfilterRegExp                            = `([0-9][0-9]*(\.[0-9]+)+)`
	//msggrepRegExp                              = `([0-9][0-9]*(\.[0-9]+)+)`
	//msginitRegExp                              = `([0-9][0-9]*(\.[0-9]+)+)`
	//msguniqRegExp                              = `([0-9][0-9]*(\.[0-9]+)+)`
	//syslogngRegExp                             = `^syslog-ng ([0-9\.]+)`
	//sarRegExp                                  = `.*sysstat-([0-9\.]+): sar.*`
	//bzip2RegExp                                = `.*bzip2-([0-9\.]+) source distribution.*`
	//cabextractRegExp                           = `^([0-9\.]+)$`
	//cpioRegExp                                 = `^([0-9]\.[0-9][0-9]*)`
	//gzipRegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//gunzipRegExp                               = `gunzip \(gzip\) ([0-9]\.[0-9][0-9]*)`
	//uncompressRegExp                           = `gunzip \(gzip\) ([0-9]\.[0-9][0-9]*)`
	//zcatRegExp                                 = `zcat \(gzip\) ([0-9]\.[0-9][0-9]*)`
	//gzexeRegExp                                = `gzexe \(gzip\) ([0-9]\.[0-9][0-9]*)`
	//zlessRegExp                                = `zless \(gzip\) ([0-9]\.[0-9][0-9]*)`
	//zmoreRegExp                                = `zmore \(gzip\) ([0-9]\.[0-9][0-9]*)`
	//znewRegExp                                 = `znew \(gzip\) ([0-9]\.[0-9][0-9]*)`
	//zcmpRegExp                                 = `zcmp \(gzip\) ([0-9]\.[0-9][0-9]*)`
	//zgrepRegExp                                = `zgrep \(gzip\) ([0-9]\.[0-9][0-9]*)`
	//zforceRegExp                               = `zforce \(gzip\) ([0-9]\.[0-9][0-9]*)`
	//zdiffRegExp                                = `z[^ ]* \(gzip\) ([0-9]\.[0-9][0-9]*)`
	//sharRegExp                                 = `^([0-9\.]+)$`
	//tarRegExp                                  = `tar \(GNU tar\) ([0-9]\.[0-9][0-9]*)`
	//rmtRegExp                                  = `rmt \(GNU tar\) ([0-9]\.[0-9][0-9]*)`
	//cdrdaoRegExp                               = `^([0-9\.]+)$`
	//mkisofsRegExp                              = `^([0-9\.]+)a([0-9\.]+)$`
	//gpgRegExp                                  = `Version: GnuPG v([0-9\.]+) `
	//gpgagentRegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//vimRegExp                                  = `VIM - Vi IMproved ([0-9\.]+) `
	//gsRegExp                                   = `ghostscript/([0-9\.]+)`
	//gocrRegExp                                 = `Optical Character Recognition --- gocr ([0-9\.]+) `
	//pdftopsRegExp                              = `^([0-9\.]+)$`
	//ncftpRegExp                                = `^.*NcFTP ([0-9\.]+)/([0-9]+) .*`
	//versionRegExp                              = `^Linux version ([0-9a-z.-]*) ([^@]*@[^)]*).*`
	//versionRegExp2                             = `^Linux version ([0-9a-z.-]*) \([^@]*@[^)]*\).*`
	//gimpRegExp                                 = `GIMP ([0-9]*\.[0-9]*\.[0-9]*)`
	//cdrdaoRegExp2                              = `^([0-9]\.[0-9\.]*)[^a-z]*$`
	//toc2cueRegExp                              = `^([0-9]\.[0-9\.]*)[^a-z]*$`
	//toc2cddbRegExp                             = `^([0-9]\.[0-9\.]*)[^a-z]*$`
	//isodebugRegExp                             = `^([0-9]\.[0-9\.]+)[^a-z]*$`
	//scgcheckRegExp                             = `^([0-9]\.[0-9\.]+)[^a-z]*$`
	//devdumpRegExp                              = `^([0-9]\.[0-9\.]+)[^a-z]*$`
	//isodumpRegExp                              = `^([0-9]\.[0-9\.]+)[^a-z]*$`
	//isovfyRegExp                               = `^([0-9]\.[0-9\.]+)[^a-z]*$`
	//kbxutilRegExp                              = `^([0-9]\.[0-9\.]+)[^a-zA-Z]*$`
	//watchgnupgRegExp                           = `watchgnupg \(GnuPG\) ([0-9]\.[0-9\.]+)[^a-zA-Z]*$`
	//gpgsmRegExp                                = `^([0-9]\.[0-9\.]+)[^a-zA-Z]*$`
	//gpgconfRegExp                              = `^([0-9]\.[0-9\.]+)[^a-zA-Z]*$`
	//pinentryRegExp                             = `^([0-9]\.[0-9\.]+)[^a-zA-Z]*$`
	//qemuRegExp                                 = `QEMU PC emulator version ([0-9]\.[0-9\.]+) .qemu.*`
	//eixRegExp                                  = `\(eix ([0-9]\.[0-9\.]+)\)`
	//eixRegExp2                                 = `eix ([0-9]\.[0-9\.]+) `
	//dvipngRegExp                               = `dvipng ([0-9]\.[0-9]+)`
	//dvigifRegExp                               = `dvipng ([0-9]\.[0-9]+)`
	//pdftoRegExp                                = `^([0-9]\.[0-9\.]+)[^a-zA-Z]*$`
	//aprRegExp                                  = `VERSION=.?([0-9]\.[0-9]\.[0-9]).?`
	//apuRegExp                                  = `VERSION=.?([0-9]\.[0-9]\.[0-9]+).?`
	//saslauthdRegExp                            = `^([0-9]\.[0-9]\.[0-9]+).*$`
	//bzcatRegExp                                = `   in the bzip2-([0-9][0-9]*(\.[0-9]+)+) source distribution.`
	//bunzip2RegExp                              = `   in the bzip2-([0-9][0-9]*(\.[0-9]+)+) source distribution.`
	//bzip2recoverRegExp                         = `bzip2recover ([0-9][0-9]*(\.[0-9]+)+): extracts blocks from damaged .bz2 files.`
	//libbz2soRegExp                             = `([0-9][0-9]*(\.[0-9]+)+). [0-9]*-.*`
	//unzipRegExp                                = `([0-9][0-9]*(\.[0-9]+)+)`
	//isoinfoRegExp                              = `^([0-9][0-9]*(\.[0-9]+)+)`
	//isoinfoRegExp2                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//mkisofsRegExp2                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//mkisofsRegExp3                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//mkhybridRegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//mkhybridRegExp2                            = `^([0-9][0-9]*(\.[0-9]+)+)`
	//gpgconnectagentRegExp                      = `^([0-9][0-9]*(\.[0-9]+)+)`
	//symcryptrunRegExp                          = `^([0-9][0-9]*(\.[0-9]+)+)`
	//pdfinfoRegExp                              = `^([0-9][0-9]*(\.[0-9]+)+)`
	//pdfimagesRegExp                            = `^([0-9][0-9]*(\.[0-9]+)+)`
	//pdffontsRegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libpopplerRegExp                           = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libsqlite3RegExp                           = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libperlsoRegExp                            = `/usr/lib/perl5/([0-9][0-9]*(\.[0-9]+)+)/`
	//libperlsoRegExp2                           = `/usr/lib64/perl5/([0-9][0-9]*(\.[0-9]+)+)/`
	//libpythonRegExp                            = `^([0-9][0-9]*\.[0-9]+\.[0-9]+)`
	//libaprRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libaprutilRegExp                           = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libsasl2soRegExp                           = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libexpatsoRegExp                           = `expat_([0-9][0-9]*(\.[0-9]+)+)`
	//glibgettextizeRegExp                       = `version=([0-9][0-9]*(\.[0-9]+)+)`
	//gmimeuuRegExp                              = `^([0-9][0-9]*(\.[0-9]+)+)`
	//gmimeconfigRegExp                          = `echo ([0-9][0-9]*(\.[0-9]+)+)`
	//libcdioparanoiaRegExp                      = `libcdio ([0-9][0-9]*(\.[0-9]+)+) `
	//mmctoolRegExp                              = `^([0-9][0-9]*(\.[0-9]+)+)`
	//isoreadRegExp                              = `^([0-9][0-9]*(\.[0-9]+)+) x86_64-pc-linux-gnu`
	//cdinfoRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+) x86_64-pc-linux-gnu`
	//isoinfoRegExp3                             = `^([0-9][0-9]*(\.[0-9]+)+) x86_64-pc-linux-gnu`
	//cdreadRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//cddriveRegExp                              = `^([0-9][0-9]*(\.[0-9]+)+) x86_64-pc-linux-gnu`
	//libcdiosoRegExp                            = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libsslsoRegExp                             = `OpenSSL ([0-9][0-9]*(\.[0-9]+)+[a-z]) [0-9]*`
	//libcryptosoRegExp                          = `OpenSSL ([0-9][0-9]*(\.[0-9]+)+[a-z]) [0-9]*`
	//unzzRegExp                                 = `version zziplib ([0-9][0-9]*(\.[0-9]+)+)`
	//zzRegExp                                   = `version zziplib ([0-9][0-9]*(\.[0-9]+)+)`
	//straceRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//gitRegExp                                  = `^([0-9][0-9]*(\.[0-9]+)+)`
	//svnRegExp                                  = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libsvnRegExp                               = `SVN/([0-9][0-9]*(\.[0-9]+)+) \(r`
	//libkdeRegExp                               = `\(KDE ([0-9][0-9]*(\.[0-9]+)+)\)`
	//muttRegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//exiv2RegExp                                = `exiv2 ([0-9][0-9]*(\.[0-9]+)+)`
	//exiv2RegExp2                               = `exiv2 ([0-9][0-9]*(\.[0-9]+)+)`
	//libasoundsoRegExp                          = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libFLACsoRegExp                            = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libgstRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libpngRegExp                               = `version=.([0-9][0-9]*(\.[0-9]+)+).`
	//libpngRegExp2                              = `version=.([0-9][0-9]*(\.[0-9]+)+).`
	//libpngRegExp3                              = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libpngRegExp4                              = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libsndfilesoRegExp                         = `libsndfile-([0-9][0-9]*(\.[0-9]+)+)`
	//libsndfilesoRegExp2                        = `libsndfile-([0-9][0-9]*(\.[0-9]+)+)`
	//zipRegExp                                  = `^([0-9][0-9]*(\.[0-9]+)+)`
	//rviRegExp                                  = `Gentoo-([0-9][0-9]*(\.[0-9]+)+)`
	//vimRegExp2                                 = `Gentoo-([0-9][0-9]*(\.[0-9]+)+)`
	//dbusbindingtoolRegExp                      = `^([0-9][0-9]*(\.[0-9]+)+)`
	//gmimeconfigRegExp2                         = `echo ([0-9][0-9]*(\.[0-9]+)+)`
	//xml2configRegExp                           = `echo ([0-9][0-9]*(\.[0-9]+)+)`
	//xsltconfigRegExp                           = `echo ([0-9][0-9]*(\.[0-9]+)+)`
	//libxsltso1126RegExp                        = `LIBXML2_([0-9][0-9]*(\.[0-9]+)+)`
	//unzipmemRegExp                             = `../../bins/unzip-mem.c version zziplib ([0-9][0-9]*(\.[0-9]+)+)`
	//libMagickCoresoRegExp2                     = `file:///usr/share/doc/imagemagick-([0-9][0-9]*(\.[0-9]+)+)/index.html`
	//libMagickCoresoRegExp3                     = `file:///usr/share/doc/imagemagick-([0-9][0-9]*(\.[0-9]+)+)/index.html`
	//libvorbissoRegExp                          = `Xiph.Org libVorbis ([0-9][0-9]*(\.[0-9]+)+)`
	//libvorbissoRegExp2                         = `Xiph.Org libVorbis ([0-9][0-9]*(\.[0-9]+)+)`
	//libvorbissoRegExp3                         = `Xiph.Org libVorbis ([0-9][0-9]*(\.[0-9]+)+)`
	//swrast_drisoRegExp                         = `%u.%u Mesa ([0-9][0-9]*(\.[0-9]+)+)`
	//libt1so512RegExp                           = `([0-9][0-9]*(\.[0-9]+)+)`
	//xinelistRegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//xineplug_inp_RegExp                        = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libxinesoRegExp2                           = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libxvidcoresoRegExp                        = `@xvid-([0-9][0-9]*(\.[0-9]+)+)`
	//vobStreamerRegExp                          = `^([0-9][0-9]*(\.[0-9]+)+)`
	//testOnDemandRTSPServerRegExp               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//testMPEG1or2SplitterRegExp                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//testMPEG4VideoToDarwinRegExp               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//MPEG2TransportStreamIndexerRegExp          = `^([0-9][0-9]*(\.[0-9]+)+)`
	//testMPEG4VideoStreamerRegExp               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//testMPEG2TransportStreamTrickPlayRegExp    = `^([0-9][0-9]*(\.[0-9]+)+)`
	//testMPEG1or2AudioVideoToDarwinRegExp       = `^([0-9][0-9]*(\.[0-9]+)+)`
	//testMPEG1or2ProgramToTransportStreamRegExp = `^([0-9][0-9]*(\.[0-9]+)+)`
	//testWAVAudioStreamerRegExp                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//openRTSPRegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//playSIPRegExp                              = `^([0-9][0-9]*(\.[0-9]+)+)`
	//testAMRAudioStreamerRegExp                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libliveMediasoRegExp                       = `^([0-9][0-9]*(\.[0-9]+)+)`
	//iptablesRegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libirc_proxysoRegExp                       = `^([0-9][0-9]*(\.[0-9]+)+)`
	//dhcpcdRegExp                               = `dhcpcd ([0-9][0-9]*(\.[0-9]+)+) starting`
	//vncviewerRegExp                            = `TightVNC Viewer version ([0-9][0-9]*(\.[0-9]+)+)`
	//XvncRegExp                                 = `TightVNC-([0-9][0-9]*(\.[0-9]+)+)`
	//wgetRegExp2                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//wgetRegExp3                                = `Wall.*(\d+\.\d+)`
	//panRegExp                                  = `pan ([0-9][0-9]*(\.[0-9]+)+)`
	//cupsdRegExp                                = `# Subscription configuration file for CUPS v([0-9][0-9]*(\.[0-9]+)+)`
	//printerscgiRegExp                          = `CUPS v([0-9][0-9]*(\.[0-9]+)+)`
	//jobscgiRegExp                              = `CUPS v([0-9][0-9]*(\.[0-9]+)+)`
	//classescgiRegExp                           = `CUPS v([0-9][0-9]*(\.[0-9]+)+)`
	//helpcgiRegExp                              = `CUPS v([0-9][0-9]*(\.[0-9]+)+)`
	//admincgiRegExp                             = `CUPS v([0-9][0-9]*(\.[0-9]+)+)`
	//libcupssoRegExp                            = `CUPS/([0-9][0-9]*(\.[0-9]+)+)`
	//libcupssoRegExp2                           = `CUPS/([0-9][0-9]*(\.[0-9]+)+)`
	//wpa_RegExp                                 = `wpa_.* v([0-9][0-9]*(\.[0-9]+)+)`
	//setfaclRegExp                              = `%s ([0-9][0-9]*(\.[0-9]+)+)`
	//getfaclRegExp                              = `%s ([0-9][0-9]*(\.[0-9]+)+)`
	//busyboxRegExp                              = `([0-9][0-9]*(\.[0-9]+)+) 20[0-9]+-[0-9]+-[0-9]+`
	//busyboxRegExp2                             = `([0-9][0-9]*(\.[0-9]+)+) 20[0-9]+-[0-9]+-[0-9]+`
	//bbRegExp                                   = `([0-9][0-9]*(\.[0-9]+)+) 20[0-9]+-[0-9]+-[0-9]+`
	//bbRegExp2                                  = `([0-9][0-9]*(\.[0-9]+)+) 20[0-9]+-[0-9]+-[0-9]+`
	//mdevRegExp                                 = `([0-9][0-9]*(\.[0-9]+)+) 20[0-9]+-[0-9]+-[0-9]+`
	//mdevRegExp2                                = `([0-9][0-9]*(\.[0-9]+)+) 20[0-9]+-[0-9]+-[0-9]+`
	//dbusRegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//dbusRegExp2                                = `D-Bus ([0-9][0-9]*(\.[0-9]+)+)`
	//libdbusRegExp                              = `D-Bus ([0-9][0-9]*(\.[0-9]+)+)`
	//edRegExp                                   = `^([0-9][0-9]*(\.[0-9]+)+)`
	//redRegExp                                  = `^([0-9][0-9]*(\.[0-9]+)+)`
	//ejectRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//findRegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//oldfindRegExp                              = `^([0-9][0-9]*(\.[0-9]+)+)`
	//xargsRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//grodviRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//grolj4RegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//grottyRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//grolbpRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//groffRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//sandboxRegExp                              = `../../sandbox-([0-9][0-9]*(\.[0-9]+)+)/libsbutil/src/string.c`
	//libsandboxsoRegExp                         = `../../sandbox-([0-9][0-9]*(\.[0-9]+)+)/libsbutil/src/debug.c`
	//texindexRegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//installinfoRegExp                          = `^([0-9][0-9]*(\.[0-9]+)+)`
	//infokeyRegExp                              = `^([0-9][0-9]*(\.[0-9]+)+)`
	//infoRegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//tunelpRegExp                               = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//tunelpRegExp2                              = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//fdformatRegExp                             = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//fdformatRegExp2                            = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//rtcwakeRegExp                              = `rtcwake from util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//rtcwakeRegExp2                             = `rtcwake from util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//readprofileRegExp                          = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//readprofileRegExp2                         = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//ldattachRegExp                             = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//ldattachRegExp2                            = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//isosizeRegExp                              = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//isosizeRegExp2                             = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//calRegExp                                  = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//calRegExp2                                 = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//renameRegExp                               = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//renameRegExp2                              = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//chrtRegExp                                 = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//chrtRegExp2                                = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//tasksetRegExp                              = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//tasksetRegExp2                             = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//ddateRegExp                                = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//ddateRegExp2                               = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//flockRegExp                                = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//flockRegExp2                               = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//scriptRegExp                               = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//scriptRegExp2                              = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//reniceRegExp                               = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//reniceRegExp2                              = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//fdiskRegExp                                = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//fdiskRegExp2                               = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//fsckminixRegExp                            = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//fsckminixRegExp2                           = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//mkfsRegExp                                 = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//mkfsRegExp2                                = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//fsckRegExp                                 = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//fsckRegExp2                                = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//sfdiskRegExp                               = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//sfdiskRegExp2                              = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//blkidRegExp                                = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//blkidRegExp2                               = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//mkswapRegExp                               = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//mkswapRegExp2                              = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//mkfsminixRegExp                            = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//mkfsminixRegExp2                           = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//blockdevRegExp                             = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//blockdevRegExp2                            = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//swapoffRegExp                              = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//swapoffRegExp2                             = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//mkfsbfsRegExp                              = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//mkfsbfsRegExp2                             = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//mkfscramfsRegExp                           = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//mkfscramfsRegExp2                          = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//cfdiskRegExp                               = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//cfdiskRegExp2                              = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//hwclockRegExp                              = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//hwclockRegExp2                             = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//swaponRegExp                               = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//swaponRegExp2                              = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//switch_rootRegExp                          = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//switch_rootRegExp2                         = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//grubinstallRegExp                          = `VERSION=([0-9][0-9]*(\.[0-9]+)+)`
	//grubsetdefaultRegExp                       = `VERSION=([0-9][0-9]*(\.[0-9]+)+)`
	//grubterminfoRegExp                         = `VERSION=([0-9][0-9]*(\.[0-9]+)+)`
	//grubRegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//asRegExp                                   = `([0-9][0-9]*(\.[0-9]+)+)`
	//libbfdsoRegExp                             = `/usr/lib64/binutils/x86_64-pc-linux-gnu/([0-9][0-9]*(\.[0-9]+)+)/debug`
	//libopcodesRegExp                           = `libopcodes-([0-9][0-9]*(\.[0-9]+)+)\.[0-9]+.so`
	//libbfdRegExp                               = `/usr/lib64/binutils/x86_64-pc-linux-gnu/([0-9][0-9]*(\.[0-9]+)+)/debug`
	//libbfdRegExp2                              = `/usr/lib/binutils/x86_64-pc-linux-gnu/([0-9][0-9]*(\.[0-9]+)+)/debug`
	//lexRegExp                                  = `^([0-9][0-9]*(\.[0-9]+)+)`
	//lexRegExp2                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//flexRegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//flexRegExp2                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//protoizeRegExp                             = `/usr/lib/gcc/[^/]*/([0-9][0-9]*(\.[0-9]+)+)/include`
	//protoizeRegExp2                            = `/usr/lib/gcc/[^/]*/([0-9][0-9]*(\.[0-9]+)+)/include`
	//unprotoizeRegExp                           = `/usr/lib/gcc/[^/]*/([0-9][0-9]*(\.[0-9]+)+)/include`
	//unprotoizeRegExp2                          = `/usr/lib/gcc/[^/]*/([0-9][0-9]*(\.[0-9]+)+)/include`
	//gdbserverRegExp                            = `^([0-9][0-9]*(\.[0-9]+)+)`
	//gettextshRegExp                            = `      version=([0-9][0-9]*(\.[0-9]+)+)`
	//msgcatRegExp                               = `([0-9][0-9]*(\.[0-9]+)+)`
	//ngettextRegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//gettextizeRegExp                           = `version=([0-9][0-9]*(\.[0-9]+)+)`
	//libgettextRegExp                           = `libgettext.*-([0-9][0-9]*(\.[0-9]+)+).so`
	//m4RegExp                                   = `GNU M4 ([0-9][0-9]*(\.[0-9]+)+)`
	//makeRegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//gmakeRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//lsattrRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//chattrRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libext2fssoRegExp                          = `^([0-9][0-9]*(\.[0-9]+)+)`
	//fsckext2RegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//e2fsckRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//fsckext4devRegExp                          = `^([0-9][0-9]*(\.[0-9]+)+)`
	//e2imageRegExp                              = `^([0-9][0-9]*(\.[0-9]+)+)`
	//mkfsext3RegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//mke2fsRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//e2labelRegExp                              = `^([0-9][0-9]*(\.[0-9]+)+)`
	//dumpe2fsRegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//fsckext4RegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//tune2fsRegExp                              = `^([0-9][0-9]*(\.[0-9]+)+)`
	//debugfsRegExp                              = `^([0-9][0-9]*(\.[0-9]+)+)`
	//mkfsext2RegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//fsckext3RegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//mkfsext4devRegExp                          = `^([0-9][0-9]*(\.[0-9]+)+)`
	//mkfsext4RegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//resize2fsRegExp                            = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libext2fssoRegExp2                         = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libfusesoRegExp                            = `^([0-9][0-9]*(\.[0-9]+)+)`
	//iconvconfigRegExp                          = `^([0-9][0-9]*(\.[0-9]+)+)`
	//rpcinfoRegExp                              = `^([0-9][0-9]*(\.[0-9]+)+)`
	//nscdRegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//lddlibc4RegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//iconvRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//localeRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//rpcgenRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//getconfRegExp                              = `^([0-9][0-9]*(\.[0-9]+)+)`
	//getentRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//localedefRegExp                            = `^([0-9][0-9]*(\.[0-9]+)+)`
	//sprofRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libthread_dbRegExp                         = `^([0-9][0-9]*(\.[0-9]+)+)`
	//ldconfigRegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libpthreadsoRegExp                         = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libpthreadRegExp                           = `^([0-9][0-9]*(\.[0-9]+)+)`
	//gencatRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//pcprofiledumpRegExp                        = `^([0-9][0-9]*(\.[0-9]+)+)`
	//slnRegExp                                  = `([0-9][0-9]*(\.[0-9]+)+)`
	//pam_cracklibsoRegExp                       = `LIBPAM_EXTENSION_([0-9][0-9]*(\.[0-9]+)+)`
	//pam_xauthsoRegExp                          = `LIBPAM_MODUTIL_([0-9][0-9]*(\.[0-9]+)+)`
	//libzsoRegExp                               = ` inflate ([0-9][0-9]*(\.[0-9]+)+) Copyright`
	//pangoRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libpangoRegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//xscreensaverRegExp                         = `^([0-9][0-9]*(\.[0-9]+)+)`
	//id3v2RegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libid3RegExp                               = `id3lib-([0-9][0-9]*(\.[0-9]+)+)`
	//id3infoRegExp                              = `^([0-9][0-9]*(\.[0-9]+)+)`
	//id3cpRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//neonconfigRegExp                           = `echo neon ([0-9][0-9]*(\.[0-9]+)+)`
	//transmissionRegExp                         = `Transmission ([0-9][0-9]*(\.[0-9]+)+)`
	//acpiRegExp                                 = `acpid-([0-9][0-9]*(\.[0-9]+)+)`
	//libbrlttyRegExp                            = `([0-9][0-9]*(\.[0-9]+)+)@`
	//catRegExp                                  = `^([0-9][0-9]*(\.[0-9]+)+)`
	//chgrpRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//chmodRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//chownRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//cpRegExp                                   = `^([0-9][0-9]*(\.[0-9]+)+)`
	//dateRegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//ddRegExp                                   = `A([0-9][0-9]*(\.[0-9]+)+)`
	//dirRegExp                                  = `^([0-9][0-9]*(\.[0-9]+)+)`
	//echoRegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//falseRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//lnRegExp                                   = `^([0-9][0-9]*(\.[0-9]+)+)`
	//lsRegExp                                   = `^([0-9][0-9]*(\.[0-9]+)+)`
	//mkdirRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//mknodRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//mvRegExp                                   = `^([0-9][0-9]*(\.[0-9]+)+)`
	//pwdRegExp                                  = `^([0-9][0-9]*(\.[0-9]+)+)`
	//readlinkRegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//rmRegExp                                   = `^([0-9][0-9]*(\.[0-9]+)+)`
	//rmdirRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//vdirRegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//syncRegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//touchRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//trueRegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//unameRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//mktempRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//installRegExp                              = `^([0-9][0-9]*(\.[0-9]+)+)`
	//hostidRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//niceRegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//whoRegExp                                  = `^([0-9][0-9]*(\.[0-9]+)+)`
	//usersRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//pinkyRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//chconRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//dircolorsRegExp                            = `^([0-9][0-9]*(\.[0-9]+)+)`
	//duRegExp                                   = `^([0-9][0-9]*(\.[0-9]+)+)`
	//linkRegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//mkfifoRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//nohupRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//shredRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//statRegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//unlinkRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//cksumRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//commRegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//csplitRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//cutRegExp                                  = `^([0-9][0-9]*(\.[0-9]+)+)`
	//expandRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//fmtRegExp                                  = `^([0-9][0-9]*(\.[0-9]+)+)`
	//foldRegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//headRegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//joinRegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//groupsRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//md5sumRegExp                               = `0123456789abcdef([0-9][0-9]*(\.[0-9]+)+)`
	//nlRegExp                                   = `^([0-9][0-9]*(\.[0-9]+)+)`
	//odRegExp                                   = `^([0-9][0-9]*(\.[0-9]+)+)`
	//pasteRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//prRegExp                                   = `^([0-9][0-9]*(\.[0-9]+)+)`
	//ptxRegExp                                  = `^([0-9][0-9]*(\.[0-9]+)+)`
	//sha1sumRegExp                              = `0123456789abcdef([0-9][0-9]*(\.[0-9]+)+)`
	//sha224sumRegExp                            = `0123456789abcdef([0-9][0-9]*(\.[0-9]+)+)`
	//sha256sumRegExp                            = `0123456789abcdef([0-9][0-9]*(\.[0-9]+)+)`
	//sha384sumRegExp                            = `0123456789abcdef([0-9][0-9]*(\.[0-9]+)+)`
	//sha512sumRegExp                            = `0123456789abcdef([0-9][0-9]*(\.[0-9]+)+)`
	//shufRegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//splitRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//tacRegExp                                  = `^([0-9][0-9]*(\.[0-9]+)+)`
	//tailRegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//trRegExp                                   = `^([0-9][0-9]*(\.[0-9]+)+)`
	//tsortRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//unexpandRegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//uniqRegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//wcRegExp                                   = `dA([0-9][0-9]*(\.[0-9]+)+)`
	//basenameRegExp                             = `^([0-46-9][0-9]*(\.[0-9]+)+)`
	//envRegExp                                  = `^([0-9][0-9]*(\.[0-9]+)+)`
	//exprRegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//factorRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//idRegExp                                   = `^([0-9][0-9]*(\.[0-9]+)+)`
	//lognameRegExp                              = `^([0-9][0-9]*(\.[0-9]+)+)`
	//pathchkRegExp                              = `^([0-9][0-9]*(\.[0-9]+)+)`
	//printenvRegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//printfRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//runconRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//teeRegExp                                  = `^([0-9][0-9]*(\.[0-9]+)+)`
	//truncateRegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//ttyRegExp                                  = `^([0-9][0-9]*(\.[0-9]+)+)`
	//whoamiRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//yesRegExp                                  = `^([0-9][0-9]*(\.[0-9]+)+)`
	//base64RegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//archRegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//chrootRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//touchRegExp2                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//mtgnuRegExp                                = `GNU cpio ([0-9][0-9]*(\.[0-9]+)+)`
	//libevolutionRegExp                         = `Evolution ([0-9][0-9]*(\.[0-9]+)+) `
	//evolutionRegExp                            = `^([0-9][0-9]*(\.[0-9]+)+)`
	//gdbRegExp                                  = `^([0-9][0-9]*\.[0-9]+(\.[0-9]+)+)`
	//gdmbinaryRegExp                            = `^([0-9][0-9]*(\.[0-9]+)+)`
	//gdmflexiserverRegExp                       = `^([0-9][0-9]*(\.[0-9]+)+)`
	//gpgsplitRegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//gpgzipRegExp                               = `VERSION=([0-9][0-9]*(\.[0-9]+)+)`
	//hpmkuriRegExp                              = `^([0-9][0-9]*(\.[0-9]+)+)`
	//iptablesRegExp2                            = `^([0-9][0-9]*(\.[0-9]+)+)`
	//ip6tablesRegExp                            = `^([0-9][0-9]*(\.[0-9]+)+)`
	//ip6tablesrestoreRegExp                     = `^([0-9][0-9]*(\.[0-9]+)+)`
	//ip6tablessaveRegExp                        = `^([0-9][0-9]*(\.[0-9]+)+)`
	//lftpRegExp                                 = `lftp/([0-9][0-9]*(\.[0-9]+)+)`
	//ltraceRegExp                               = `ltrace version ([0-9][0-9]*(\.[0-9]+)+).`
	//libaudioscrobblersoRegExp                  = `Rhythmbox/([0-9][0-9]*(\.[0-9]+)+)`
	//libdaapsoRegExp                            = `Rhythmbox ([0-9][0-9]*(\.[0-9]+)+)`
	//libmtpdevicesoRegExp                       = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libfmradiosoRegExp                         = `^([0-9][0-9]*(\.[0-9]+)+)`
	//rhythmboxRegExp                            = `^([0-9][0-9]*(\.[0-9]+)+)`
	//rsyncRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//imuxsocksoRegExp                           = `^([0-9][0-9]*(\.[0-9]+)+)`
	//imuxsocksoRegExp2                          = `^([0-9][0-9]*(\.[0-9]+)+)`
	//ommailsoRegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//ommailsoRegExp2                            = `^([0-9][0-9]*(\.[0-9]+)+)`
	//sudoRegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+(p[0-9]*)?)`
	//visudoRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+(p[0-9]*)?)`
	//vinagreRegExp                              = `^([0-9][0-9]*(\.[0-9]+)+)`
	//w3mRegExp                                  = `w3m/([0-9][0-9]*(\.[0-9]+)+)`
	//xinputRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//xsaneRegExp                                = `xsane-([0-9][0-9]*(\.[0-9]+)+)`
	//xmlRegExp                                  = `^([0-9][0-9]*(\.[0-9]+)+)`
	//xmlstarletRegExp                           = `^([0-9][0-9]*(\.[0-9]+)+)`
	//ndisasmRegExp                              = `NASM ([0-9][0-9]*(\.[0-9]+)+)`
	//ndisasmRegExp2                             = `NASM ([0-9][0-9]*(\.[0-9]+)+)`
	//cddriveRegExp2                             = `^([0-9][0-9]*(\.[0-9]+)+) `
	//cdinfoRegExp2                              = `^([0-9][0-9]*(\.[0-9]+)+) `
	//isoinfoRegExp4                             = `^([0-9][0-9]*(\.[0-9]+)+) `
	//isoreadRegExp2                             = `^([0-9][0-9]*(\.[0-9]+)+) `
	//libtasn1soRegExp                           = `^([0-9][0-9]*(\.[0-9]+)+)`
	//asn1RegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libgconf2soRegExp                          = `^([0-9][0-9]*(\.[0-9]+)+)`
	//gconftool2RegExp                           = `^([0-9][0-9]*(\.[0-9]+)+)`
	//gdmRegExp                                  = `GDM ([0-9][0-9]*(\.[0-9]+)+)`
	//libgtop20soRegExp                          = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libgtop20soRegExp2                         = `^([0-9][0-9]*(\.[0-9]+)+)`
	//formailRegExp                              = ` v([0-9][0-9]*(\.[0-9]+)+) 20`
	//postaliasRegExp                            = `^([0-9][0-9]*(\.[0-9]+)+)`
	//postcatRegExp                              = `^([0-9][0-9]*(\.[0-9]+)+)`
	//postfixRegExp                              = `^([0-9][0-9]*(\.[0-9]+)+)`
	//postkickRegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//postlogRegExp                              = `^([0-9][0-9]*(\.[0-9]+)+)`
	//postmapRegExp                              = `^([0-9][0-9]*(\.[0-9]+)+)`
	//postmultiRegExp                            = `^([0-9][0-9]*(\.[0-9]+)+)`
	//postsuperRegExp                            = `^([0-9][0-9]*(\.[0-9]+)+)`
	//postdropRegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//postqueueRegExp                            = `^([0-9][0-9]*(\.[0-9]+)+)`
	//faadRegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//imlib2configRegExp                         = `echo ([0-9][0-9]*(\.[0-9]+)+)`
	//xineRegExp                                 = `^([0-9][0-9]*(\.[0-9]+)+)`
	//fbxineRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//nfsstatRegExp                              = `nfsstat: ([0-9][0-9]*(\.[0-9]+)+)`
	//rpcmountdRegExp                            = `^([0-9][0-9]*(\.[0-9]+)+)`
	//showmountRegExp                            = `showmount for ([0-9][0-9]*(\.[0-9]+)+)`
	//rpcstatdRegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//irssiRegExp                                = `irssi ([0-9][0-9]*(\.[0-9]+)+)`
	//aptRegExp                                  = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//aptRegExp2                                 = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//idljRegExp                                 = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//idljRegExp2                                = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//keytoolRegExp                              = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//keytoolRegExp2                             = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//jarsignerRegExp                            = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//jarsignerRegExp2                           = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//policytoolRegExp                           = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//policytoolRegExp2                          = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//jarRegExp                                  = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//jarRegExp2                                 = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//xjcRegExp                                  = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//xjcRegExp2                                 = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//schemagenRegExp                            = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//schemagenRegExp2                           = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//wsgenRegExp                                = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//wsgenRegExp2                               = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//wsimportRegExp                             = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//wsimportRegExp2                            = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//appletviewerRegExp                         = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//appletviewerRegExp2                        = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//rmicRegExp                                 = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//rmicRegExp2                                = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//rmiregistryRegExp                          = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//rmiregistryRegExp2                         = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//rmidRegExp                                 = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//rmidRegExp2                                = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//native2asciiRegExp                         = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//native2asciiRegExp2                        = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//serialverRegExp                            = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//serialverRegExp2                           = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//jpsRegExp                                  = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//jpsRegExp2                                 = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//jstatRegExp                                = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//jstatRegExp2                               = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//jstatdRegExp                               = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//jstatdRegExp2                              = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//jsadebugdRegExp                            = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//jsadebugdRegExp2                           = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//jstackRegExp                               = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//jstackRegExp2                              = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//jmapRegExp                                 = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//jmapRegExp2                                = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//jinfoRegExp                                = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//jinfoRegExp2                               = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//jconsoleRegExp                             = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//jconsoleRegExp2                            = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//jrunscriptRegExp                           = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//jrunscriptRegExp2                          = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//jhatRegExp                                 = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//jhatRegExp2                                = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//tnameservRegExp                            = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//tnameservRegExp2                           = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//orbdRegExp                                 = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//orbdRegExp2                                = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//servertoolRegExp                           = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//servertoolRegExp2                          = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//pack200RegExp                              = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//pack200RegExp2                             = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//extcheckRegExp                             = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//extcheckRegExp2                            = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//jdbRegExp                                  = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//jdbRegExp2                                 = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//keytoolRegExp3                             = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//keytoolRegExp4                             = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//policytoolRegExp3                          = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//policytoolRegExp4                          = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//rmiregistryRegExp3                         = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//rmiregistryRegExp4                         = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//rmidRegExp3                                = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//rmidRegExp4                                = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//tnameservRegExp3                           = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//tnameservRegExp4                           = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//orbdRegExp3                                = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//orbdRegExp4                                = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//servertoolRegExp3                          = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//servertoolRegExp4                          = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//pack200RegExp3                             = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//pack200RegExp4                             = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//java_vmRegExp                              = `JAVA_PLUGIN_VERSION=([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//java_vmRegExp2                             = `JAVA_PLUGIN_VERSION=([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//libjavasoRegExp                            = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//libjavasoRegExp2                           = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//libjavaplugin_nscp_gcc29soRegExp           = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//libjavaplugin_nscp_gcc29soRegExp2          = `([0-9][0-9]*(\.[0-9]+)+)_([0-9]+)`
	//mod_sslsoRegExp                            = `mod_ssl/([0-9][0-9]*(\.[0-9]+)+)`
	//xinputRegExp2                              = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libvirtdRegExp                             = `([0-9][0-9]*(\.[0-9]+)+)`
	//libvirtsoRegExp                            = `LIBVIRT_PRIVATE_([0-9][0-9]*(\.[0-9]+)+)`
	//libvirtqemusoRegExp                        = `LIBVIRT_PRIVATE_([0-9][0-9]*(\.[0-9]+)+)`
	//dnsmasqRegExp                              = `dnsmasq-([0-9][0-9]*(\.[0-9]+)+)`
	//gnutlsRegExp                               = `GnuTLS ([0-9][0-9]*(\.[0-9]+)+)`
	//psktoolRegExp                              = `GnuTLS ([0-9][0-9]*(\.[0-9]+)+)`
	//srptoolRegExp                              = `GnuTLS ([0-9][0-9]*(\.[0-9]+)+)`
	//certtoolRegExp                             = `GnuTLS ([0-9][0-9]*(\.[0-9]+)+)`
	//libgnutlsextrasoRegExp                     = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libgnutlssoRegExp                          = `Version: OpenPrivacy ([0-9][0-9]*(\.[0-9]+)+)%s`
	//makeinfoRegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libtoolRegExp                              = `VERSION=([0-9][0-9]*(\.[0-9]+)+)`
	//linksRegExp                                = `gif2png ([0-9][0-9]*(\.[0-9]+)+)`
	//linksRegExp2                               = `gif2png ([0-9][0-9]*(\.[0-9]+)+)`
	//_cairosoRegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//resolve_stack_dumpRegExp                   = `^([0-9][0-9]*(\.[0-9]+)+)`
	//mysqlRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libphp5soRegExp                            = `PHP/([0-9][0-9]*(\.[0-9]+)+)-pl0-gentoo`
	//phpRegExp                                  = `X-Powered-By: PHP/([0-9][0-9]*(\.[0-9]+)+)-`
	//libmcryptsoRegExp                          = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libmountsoRegExp                           = `([0-9][0-9]*(\.[0-9]+)+).0`
	//libblkidsoRegExp                           = `([0-9][0-9]*(\.[0-9]+)+).0`
	//umountRegExp                               = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//mountRegExp                                = `util-linux-ng ([0-9][0-9]*(\.[0-9]+)+)`
	//findmntRegExp                              = `MOUNT_([0-9][0-9]*(\.[0-9]+)+)`
	//aureportRegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//ausearchRegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//auditdRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//auditctlRegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libmysqlclient_rsoRegExp                   = `([0-9][0-9]*(\.[0-9]+)+)`
	//libmysqlclientsoRegExp                     = `([0-9][0-9]*(\.[0-9]+)+)`
	//bsdcpioRegExp                              = `^([0-9][0-9]*(\.[0-9]+)+)`
	//bsdtarRegExp                               = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libarchivesoRegExp                         = `libarchive ([0-9][0-9]*(\.[0-9]+)+)`
	//namedRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libiscsoRegExp                             = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libisccfgsoRegExp                          = `^([0-9][0-9]*(\.[0-9]+)+)`
	//libbind9soRegExp                           = `^([0-9][0-9]*(\.[0-9]+)+)`
	//liblwressoRegExp                           = `^([0-9][0-9]*(\.[0-9]+)+)`
	//courierimapdRegExp                         = `Courier-IMAP ([0-9][0-9]*(\.[0-9]+)+)/.*`
	//newroleRegExp                              = `^([0-9][0-9]*(\.[0-9]+)+)`
	//seconRegExp                                = `^([0-9][0-9]*(\.[0-9]+)+)`
	//lighttpdRegExp                             = `Server: lighttpd/([0-9][0-9]*(\.[0-9]+)+)`
	//moddirlistingsoRegExp                      = `lighttpd/([0-9][0-9]*(\.[0-9]+)+)`
	//mod_cgisoRegExp                            = `lighttpd/([0-9][0-9]*(\.[0-9]+)+)`
	//mod_scgisoRegExp                           = `lighttpd/([0-9][0-9]*(\.[0-9]+)+)`
	//mod_fastcgisoRegExp                        = `lighttpd/([0-9][0-9]*(\.[0-9]+)+)`
	//mod_ssisoRegExp                            = `lighttpd/([0-9][0-9]*(\.[0-9]+)+)`
)

var ExesInfo = map[string]*aquatypes.ExecutableDetails{
	"bash":                                 {Vendor: "bash", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{bashRegExp}}},
	"wget":                                 {Vendor: "wget", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{wgetRegExp, wgetRegExp2, wgetRegExp3}}},
	"7za":                                  {Vendor: "p7zip", Package: "7-zip", Constraints: &aquatypes.Constraints{RegexMatch: []string{zaRegExp}}},
	"node":                                 {Vendor: "node.js", Package: "nodejs", Constraints: &aquatypes.Constraints{RegexMatch: []string{nodeRegExp}}},
	"version.sh":                           {Vendor: "tomcat", Package: "apache", Constraints: &aquatypes.Constraints{RegexMatch: []string{tomcatRegExp}}},
	"perl":                                 {Vendor: "perl", Package: "perl", Constraints: &aquatypes.Constraints{RegexMatch: []string{perlRegExp}}},
	"perlivp":                              {Vendor: "perl", Package: "perl", Constraints: &aquatypes.Constraints{RegexMatch: []string{perlivpRegExp}}},
	"java":                                 {Vendor: "jre", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{javaRegExp}}},
	"gdlib-config":                         {Vendor: "gd_graphics_library", Package: "libgd", Constraints: &aquatypes.Constraints{RegexMatch: []string{gdlibconfigRegExp}}},
	"fetchmail":                            {Vendor: "fetchmail", Package: "eric_raymond", Constraints: &aquatypes.Constraints{RegexMatch: []string{fetchmailRegExp}}},
	"nano":                                 {Vendor: "nano", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{nanoRegExp}}},
	"rnano":                                {Vendor: "nano", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{rnanoRegExp}}},
	"wireshark":                            {Vendor: "wireshark", Package: "wireshark", Constraints: &aquatypes.Constraints{RegexMatch: []string{wiresharkRegExp}}},
	"libxine.so":                           {Vendor: "xine-lib", Package: "xine", Constraints: &aquatypes.Constraints{RegexMatch: []string{libxinesoRegExp, gmimeconfigRegExp2}}},
	"libMagickCore.so":                     {Vendor: "imagemagick", Package: "imagemagick", Constraints: &aquatypes.Constraints{RegexMatch: []string{libMagickCoresoRegExp, libMagickCoresoRegExp2, libMagickCoresoRegExp3}}},
	"libruby.so":                           {Vendor: "ruby", Package: "ruby-lang", Constraints: &aquatypes.Constraints{RegexMatch: []string{librubysoRegExp}}},
	"libflashplayer.so":                    {Vendor: "flash_player", Package: "adobe", Constraints: &aquatypes.Constraints{RegexMatch: []string{libflashplayersoRegExp}}},
	"openssl":                              {Vendor: "openssl", Package: "openssl", Constraints: &aquatypes.Constraints{RegexMatch: []string{opensslRegExp}}},
	"gettext":                              {Vendor: "gettext", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{gettextRegExp}}},
	"envsubst":                             {Vendor: "gettext", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{envsubstRegExp}}},
	"msgcmp":                               {Vendor: "gettext", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{msgcmpRegExp}}},
	"msgfmt":                               {Vendor: "gettext", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{msgfmtRegExp}}},
	"msgmerge":                             {Vendor: "gettext", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{msgmergeRegExp}}},
	"msgunfmt":                             {Vendor: "gettext", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{msgunfmtRegExp}}},
	"xgettext":                             {Vendor: "gettext", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{xgettextRegExp}}},
	"msgattrib":                            {Vendor: "gettext", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{msgattribRegExp}}},
	"msgcomm":                              {Vendor: "gettext", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{msgcommRegExp}}},
	"msgconv":                              {Vendor: "gettext", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{msgconvRegExp}}},
	"msgen":                                {Vendor: "gettext", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{msgenRegExp}}},
	"msgexec":                              {Vendor: "gettext", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{msgexecRegExp}}},
	"msgfilter":                            {Vendor: "gettext", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{msgfilterRegExp}}},
	"msggrep":                              {Vendor: "gettext", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{msggrepRegExp}}},
	"msginit":                              {Vendor: "gettext", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{msginitRegExp}}},
	"msguniq":                              {Vendor: "gettext", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{msguniqRegExp}}},
	"syslog-ng":                            {Vendor: "syslog-ng_open_source_edition", Package: "balabit", Constraints: &aquatypes.Constraints{RegexMatch: []string{syslogngRegExp}}},
	"sar":                                  {Vendor: "sysstat", Package: "sysstat", Constraints: &aquatypes.Constraints{RegexMatch: []string{sarRegExp}}},
	"bzip2":                                {Vendor: "bzip2", Package: "bzip", Constraints: &aquatypes.Constraints{RegexMatch: []string{bzip2RegExp}}},
	"cabextract":                           {Vendor: "cabextract", Package: "cabextract", Constraints: &aquatypes.Constraints{RegexMatch: []string{cabextractRegExp}}},
	"cpio":                                 {Vendor: "cpio", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{cpioRegExp}}},
	"gzip":                                 {Vendor: "gzip", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{gzipRegExp}}},
	"gunzip":                               {Vendor: "gzip", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{gunzipRegExp}}},
	"uncompress":                           {Vendor: "gzip", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{uncompressRegExp}}},
	"zcat":                                 {Vendor: "gzip", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{zcatRegExp}}},
	"gzexe":                                {Vendor: "gzip", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{gzexeRegExp}}},
	"zless":                                {Vendor: "gzip", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{zlessRegExp}}},
	"zmore":                                {Vendor: "gzip", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{zmoreRegExp}}},
	"znew":                                 {Vendor: "gzip", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{znewRegExp}}},
	"zcmp":                                 {Vendor: "gzip", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{zcmpRegExp}}},
	"zgrep":                                {Vendor: "gzip", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{zgrepRegExp}}},
	"zforce":                               {Vendor: "gzip", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{zforceRegExp}}},
	"zdiff":                                {Vendor: "gzip", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{zdiffRegExp}}},
	"shar":                                 {Vendor: "sharutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{sharRegExp}}},
	"tar":                                  {Vendor: "tar", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{tarRegExp}}},
	"rmt":                                  {Vendor: "tar", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{rmtRegExp}}},
	"cdrdao":                               {Vendor: "cdrdao", Package: "andreas_mueller", Constraints: &aquatypes.Constraints{RegexMatch: []string{cdrdaoRegExp, cdrdaoRegExp2}}},
	"mkisofs":                              {Vendor: "cdrecord", Package: "cdrtools", Constraints: &aquatypes.Constraints{RegexMatch: []string{mkisofsRegExp, mkisofsRegExp2, mkisofsRegExp3}}},
	"gpg":                                  {Vendor: "gnupg", Package: "gnupg", Constraints: &aquatypes.Constraints{RegexMatch: []string{gpgRegExp}}},
	"gpg-agent":                            {Vendor: "gnupg", Package: "gnupg", Constraints: &aquatypes.Constraints{RegexMatch: []string{gpgagentRegExp}}},
	"vim":                                  {Vendor: "vim", Package: "vim", Constraints: &aquatypes.Constraints{RegexMatch: []string{vimRegExp, vimRegExp2}}},
	"gs":                                   {Vendor: "ghostscript", Package: "ghostscript", Constraints: &aquatypes.Constraints{RegexMatch: []string{gsRegExp}}},
	"gocr":                                 {Vendor: "optical_character_recognition_utility", Package: "gocr", Constraints: &aquatypes.Constraints{RegexMatch: []string{gocrRegExp}}},
	"pdftops":                              {Vendor: "poppler", Package: "poppler", Constraints: &aquatypes.Constraints{RegexMatch: []string{pdftopsRegExp}}},
	"ncftp":                                {Vendor: "ncftp", Package: "ncftp_software", Constraints: &aquatypes.Constraints{RegexMatch: []string{ncftpRegExp}}},
	"version":                              {Vendor: "linux_kernel", Package: "version", Constraints: &aquatypes.Constraints{RegexMatch: []string{versionRegExp, versionRegExp2}}},
	"gimp":                                 {Vendor: "gimp", Package: "gimp", Constraints: &aquatypes.Constraints{RegexMatch: []string{gimpRegExp}}},
	"toc2cue":                              {Vendor: "cdrdao", Package: "andreas_mueller", Constraints: &aquatypes.Constraints{RegexMatch: []string{toc2cueRegExp}}},
	"toc2cddb":                             {Vendor: "cdrdao", Package: "andreas_mueller", Constraints: &aquatypes.Constraints{RegexMatch: []string{toc2cddbRegExp}}},
	"isodebug":                             {Vendor: "cdrecord", Package: "cdrtools", Constraints: &aquatypes.Constraints{RegexMatch: []string{isodebugRegExp}}},
	"scgcheck":                             {Vendor: "cdrecord", Package: "cdrtools", Constraints: &aquatypes.Constraints{RegexMatch: []string{scgcheckRegExp}}},
	"devdump":                              {Vendor: "cdrecord", Package: "cdrtools", Constraints: &aquatypes.Constraints{RegexMatch: []string{devdumpRegExp}}},
	"isodump":                              {Vendor: "cdrecord", Package: "cdrtools", Constraints: &aquatypes.Constraints{RegexMatch: []string{isodumpRegExp}}},
	"isovfy":                               {Vendor: "cdrecord", Package: "cdrtools", Constraints: &aquatypes.Constraints{RegexMatch: []string{isovfyRegExp}}},
	"kbxutil":                              {Vendor: "gnupg", Package: "gnupg", Constraints: &aquatypes.Constraints{RegexMatch: []string{kbxutilRegExp}}},
	"watchgnupg":                           {Vendor: "gnupg", Package: "gnupg", Constraints: &aquatypes.Constraints{RegexMatch: []string{watchgnupgRegExp}}},
	"gpgsm":                                {Vendor: "gnupg", Package: "gnupg", Constraints: &aquatypes.Constraints{RegexMatch: []string{gpgsmRegExp}}},
	"gpgconf":                              {Vendor: "gnupg", Package: "gnupg", Constraints: &aquatypes.Constraints{RegexMatch: []string{gpgconfRegExp}}},
	"pinentry":                             {Vendor: "app-crypt_pinentry", Package: "gentoo", Constraints: &aquatypes.Constraints{RegexMatch: []string{pinentryRegExp}}},
	"qemu":                                 {Vendor: "qemu", Package: "qemu", Constraints: &aquatypes.Constraints{RegexMatch: []string{qemuRegExp}}},
	"eix":                                  {Vendor: "linux_eix", Package: "gentoo", Constraints: &aquatypes.Constraints{RegexMatch: []string{eixRegExp, eixRegExp2}}},
	"dvipng":                               {Vendor: "dvipng", Package: "jan_ake-larsson", Constraints: &aquatypes.Constraints{RegexMatch: []string{dvipngRegExp}}},
	"dvigif":                               {Vendor: "dvipng", Package: "jan_ake-larsson", Constraints: &aquatypes.Constraints{RegexMatch: []string{dvigifRegExp}}},
	"pdfto":                                {Vendor: "poppler", Package: "poppler", Constraints: &aquatypes.Constraints{RegexMatch: []string{pdftoRegExp}}},
	"apr":                                  {Vendor: "apr", Package: "apache", Constraints: &aquatypes.Constraints{RegexMatch: []string{aprRegExp}}},
	"apu":                                  {Vendor: "apr-util", Package: "apache", Constraints: &aquatypes.Constraints{RegexMatch: []string{apuRegExp}}},
	"saslauthd":                            {Vendor: "cyrus-sasl", Package: "carnegie_mellon_university", Constraints: &aquatypes.Constraints{RegexMatch: []string{saslauthdRegExp}}},
	"bzcat":                                {Vendor: "bzip", Package: "bzip2", Constraints: &aquatypes.Constraints{RegexMatch: []string{bzcatRegExp}}},
	"bunzip2":                              {Vendor: "bzip", Package: "bzip2", Constraints: &aquatypes.Constraints{RegexMatch: []string{bunzip2RegExp}}},
	"bzip2recover":                         {Vendor: "bzip", Package: "bzip2", Constraints: &aquatypes.Constraints{RegexMatch: []string{bzip2recoverRegExp}}},
	"libbz2.so":                            {Vendor: "bzip", Package: "bzip2", Constraints: &aquatypes.Constraints{RegexMatch: []string{libbz2soRegExp}}},
	"unzip":                                {Vendor: "unzip", Package: "info-zip", Constraints: &aquatypes.Constraints{RegexMatch: []string{unzipRegExp}}},
	"isoinfo":                              {Vendor: "cdrecord", Package: "cdrtools", Constraints: &aquatypes.Constraints{RegexMatch: []string{isoinfoRegExp, isoinfoRegExp2}}},
	"mkhybrid":                             {Vendor: "cdrecord", Package: "cdrtools", Constraints: &aquatypes.Constraints{RegexMatch: []string{mkhybridRegExp, mkhybridRegExp2}}},
	"gpg-connect-agent":                    {Vendor: "gnupg", Package: "gnupg", Constraints: &aquatypes.Constraints{RegexMatch: []string{gpgconnectagentRegExp}}},
	"symcryptrun":                          {Vendor: "gnupg", Package: "gnupg", Constraints: &aquatypes.Constraints{RegexMatch: []string{symcryptrunRegExp}}},
	"pdfinfo":                              {Vendor: "poppler", Package: "poppler", Constraints: &aquatypes.Constraints{RegexMatch: []string{pdfinfoRegExp}}},
	"pdfimages":                            {Vendor: "poppler", Package: "poppler", Constraints: &aquatypes.Constraints{RegexMatch: []string{pdfimagesRegExp}}},
	"pdffonts":                             {Vendor: "poppler", Package: "poppler", Constraints: &aquatypes.Constraints{RegexMatch: []string{pdffontsRegExp}}},
	"libpoppler":                           {Vendor: "poppler", Package: "poppler", Constraints: &aquatypes.Constraints{RegexMatch: []string{libpopplerRegExp}}},
	"libsqlite3":                           {Vendor: "sqlite", Package: "sqlite", Constraints: &aquatypes.Constraints{RegexMatch: []string{libsqlite3RegExp}}},
	"libperl.so":                           {Vendor: "perl", Package: "perl", Constraints: &aquatypes.Constraints{RegexMatch: []string{libperlsoRegExp, libperlsoRegExp2}}},
	"libpython":                            {Vendor: "python", Package: "python", Constraints: &aquatypes.Constraints{RegexMatch: []string{libpythonRegExp}}},
	"libapr-":                              {Vendor: "apr-util", Package: "apache", Constraints: &aquatypes.Constraints{RegexMatch: []string{libaprRegExp}}},
	"libaprutil-":                          {Vendor: "apr-util", Package: "apache", Constraints: &aquatypes.Constraints{RegexMatch: []string{libaprutilRegExp}}},
	"libsasl2.so":                          {Vendor: "cyrus-sasl", Package: "carnegie_mellon_university", Constraints: &aquatypes.Constraints{RegexMatch: []string{libsasl2soRegExp}}},
	"glib-gettextize":                      {Vendor: "glib", Package: "gnome", Constraints: &aquatypes.Constraints{RegexMatch: []string{glibgettextizeRegExp}}},
	"gmime-uu":                             {Vendor: "gmime", Package: "gnome", Constraints: &aquatypes.Constraints{RegexMatch: []string{gmimeuuRegExp}}},
	"gmime-config":                         {Vendor: "gmime", Package: "gnome", Constraints: &aquatypes.Constraints{RegexMatch: []string{gmimeconfigRegExp, gmimeconfigRegExp2}}},
	"libcdio-paranoia":                     {Vendor: "libcdio", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{libcdioparanoiaRegExp}}},
	"mmc-tool":                             {Vendor: "libcdio", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{mmctoolRegExp}}},
	"iso-read":                             {Vendor: "libcdio", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{isoreadRegExp, isoreadRegExp2}}},
	"cd-info":                              {Vendor: "libcdio", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{cdinfoRegExp, cdinfoRegExp2}}},
	"iso-info":                             {Vendor: "libcdio", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{isoinfoRegExp, cddriveRegExp2}}},
	"cd-read":                              {Vendor: "libcdio", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{cdreadRegExp}}},
	"cd-drive":                             {Vendor: "libcdio", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{cddriveRegExp, cddriveRegExp2}}},
	"libcdio.so":                           {Vendor: "libcdio", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{libcdiosoRegExp}}},
	"libssl.so":                            {Vendor: "openssl", Package: "openssl", Constraints: &aquatypes.Constraints{RegexMatch: []string{libsslsoRegExp}}},
	"libcrypto.so":                         {Vendor: "openssl", Package: "openssl", Constraints: &aquatypes.Constraints{RegexMatch: []string{libcryptosoRegExp}}},
	"unzz":                                 {Vendor: "zziplib", Package: "zziplib", Constraints: &aquatypes.Constraints{RegexMatch: []string{unzzRegExp}}},
	"zz":                                   {Vendor: "zziplib", Package: "zziplib", Constraints: &aquatypes.Constraints{RegexMatch: []string{zzRegExp}}},
	"strace":                               {Vendor: "strace", Package: "paul_kranenburg", Constraints: &aquatypes.Constraints{RegexMatch: []string{straceRegExp}}},
	"git":                                  {Vendor: "git", Package: "git", Constraints: &aquatypes.Constraints{RegexMatch: []string{gitRegExp}}},
	"svn":                                  {Vendor: "subversion", Package: "subversion", Constraints: &aquatypes.Constraints{RegexMatch: []string{svnRegExp}}},
	"libsvn":                               {Vendor: "subversion", Package: "subversion", Constraints: &aquatypes.Constraints{RegexMatch: []string{libsvnRegExp}}},
	"libkde":                               {Vendor: "kdelibs", Package: "kde", Constraints: &aquatypes.Constraints{RegexMatch: []string{libkdeRegExp}}},
	"mutt":                                 {Vendor: "mutt", Package: "mutt", Constraints: &aquatypes.Constraints{RegexMatch: []string{muttRegExp}}},
	"exiv2":                                {Vendor: "exiv2", Package: "andreas_huggel", Constraints: &aquatypes.Constraints{RegexMatch: []string{exiv2RegExp, exiv2RegExp2}}},
	"libasound.so":                         {Vendor: "alsa-lib", Package: "alsa", Constraints: &aquatypes.Constraints{RegexMatch: []string{libasoundsoRegExp}}},
	"libFLAC.so":                           {Vendor: "libflac", Package: "flac", Constraints: &aquatypes.Constraints{RegexMatch: []string{libFLACsoRegExp}}},
	"libgst":                               {Vendor: "gst-plugins-base", Package: "gstreamer", Constraints: &aquatypes.Constraints{RegexMatch: []string{libgstRegExp}}},
	"libpng":                               {Vendor: "libpng", Package: "libpng", Constraints: &aquatypes.Constraints{RegexMatch: []string{libpngRegExp, libpngRegExp2, libpngRegExp3, libpngRegExp4}}},
	"libsndfile.so":                        {Vendor: "libsndfile", Package: "gentoo", Constraints: &aquatypes.Constraints{RegexMatch: []string{libsndfilesoRegExp, libsndfilesoRegExp2}}},
	"zip":                                  {Vendor: "zip", Package: "info-zip", Constraints: &aquatypes.Constraints{RegexMatch: []string{zipRegExp}}},
	"rvi":                                  {Vendor: "vim", Package: "vim", Constraints: &aquatypes.Constraints{RegexMatch: []string{rviRegExp}}},
	"dbus-binding-tool":                    {Vendor: "", Package: "", Constraints: &aquatypes.Constraints{RegexMatch: []string{dbusbindingtoolRegExp}}},
	"xml2-config":                          {Vendor: "libxml2", Package: "xmlsoft", Constraints: &aquatypes.Constraints{RegexMatch: []string{xml2configRegExp}}},
	"xslt-config":                          {Vendor: "libxslt", Package: "xmlsoft", Constraints: &aquatypes.Constraints{RegexMatch: []string{xsltconfigRegExp}}},
	"libxslt.so.1.1.26":                    {Vendor: "libxslt", Package: "xmlsoft", Constraints: &aquatypes.Constraints{RegexMatch: []string{libxsltso1126RegExp}}},
	"unzip-mem":                            {Vendor: "zziplib", Package: "zziplib", Constraints: &aquatypes.Constraints{RegexMatch: []string{unzipmemRegExp}}},
	"libvorbis.so":                         {Vendor: "libvorbis", Package: "libvorbis", Constraints: &aquatypes.Constraints{RegexMatch: []string{libvorbissoRegExp, libvorbissoRegExp2, libvorbissoRegExp3}}},
	"swrast_dri.so":                        {Vendor: "mesa", Package: "brian_paul", Constraints: &aquatypes.Constraints{RegexMatch: []string{swrast_drisoRegExp}}},
	"libt1.so.5.1.2":                       {Vendor: "t1lib", Package: "t1lib", Constraints: &aquatypes.Constraints{RegexMatch: []string{libt1so512RegExp}}},
	"xine-list":                            {Vendor: "xine-lib", Package: "xine", Constraints: &aquatypes.Constraints{RegexMatch: []string{xinelistRegExp}}},
	"xineplug_inp_":                        {Vendor: "xine-lib", Package: "xine", Constraints: &aquatypes.Constraints{RegexMatch: []string{xineplug_inp_RegExp}}},
	"libxvidcore.so":                       {Vendor: "xvid", Package: "xvid", Constraints: &aquatypes.Constraints{RegexMatch: []string{libxvidcoresoRegExp}}},
	"vobStreamer":                          {Vendor: "media_server", Package: "live555", Constraints: &aquatypes.Constraints{RegexMatch: []string{vobStreamerRegExp}}},
	"testOnDemandRTSPServer":               {Vendor: "media_server", Package: "live555", Constraints: &aquatypes.Constraints{RegexMatch: []string{testOnDemandRTSPServerRegExp}}},
	"testMPEG1or2Splitter":                 {Vendor: "media_server", Package: "live555", Constraints: &aquatypes.Constraints{RegexMatch: []string{testMPEG1or2SplitterRegExp}}},
	"testMPEG4VideoToDarwin":               {Vendor: "media_server", Package: "live555", Constraints: &aquatypes.Constraints{RegexMatch: []string{testMPEG4VideoToDarwinRegExp}}},
	"MPEG2TransportStreamIndexer":          {Vendor: "media_server", Package: "live555", Constraints: &aquatypes.Constraints{RegexMatch: []string{MPEG2TransportStreamIndexerRegExp}}},
	"testMPEG4VideoStreamer":               {Vendor: "media_server", Package: "live555", Constraints: &aquatypes.Constraints{RegexMatch: []string{testMPEG4VideoStreamerRegExp}}},
	"testMPEG2TransportStreamTrickPlay":    {Vendor: "media_server", Package: "live555", Constraints: &aquatypes.Constraints{RegexMatch: []string{testMPEG2TransportStreamTrickPlayRegExp}}},
	"testMPEG1or2AudioVideoToDarwin":       {Vendor: "media_server", Package: "live555", Constraints: &aquatypes.Constraints{RegexMatch: []string{testMPEG1or2AudioVideoToDarwinRegExp}}},
	"testMPEG1or2ProgramToTransportStream": {Vendor: "media_server", Package: "live555", Constraints: &aquatypes.Constraints{RegexMatch: []string{testMPEG1or2ProgramToTransportStreamRegExp}}},
	"testWAVAudioStreamer":                 {Vendor: "media_server", Package: "live555", Constraints: &aquatypes.Constraints{RegexMatch: []string{testWAVAudioStreamerRegExp}}},
	"openRTSP":                             {Vendor: "media_server", Package: "live555", Constraints: &aquatypes.Constraints{RegexMatch: []string{openRTSPRegExp}}},
	"playSIP":                              {Vendor: "media_server", Package: "live555", Constraints: &aquatypes.Constraints{RegexMatch: []string{playSIPRegExp}}},
	"testAMRAudioStreamer":                 {Vendor: "media_server", Package: "live555", Constraints: &aquatypes.Constraints{RegexMatch: []string{testAMRAudioStreamerRegExp}}},
	"libliveMedia.so":                      {Vendor: "media_server", Package: "live555", Constraints: &aquatypes.Constraints{RegexMatch: []string{libliveMediasoRegExp}}},
	"libirc_proxy.so":                      {Vendor: "", Package: "", Constraints: &aquatypes.Constraints{RegexMatch: []string{libirc_proxysoRegExp}}},
	"dhcpcd":                               {Vendor: "dhcpcd", Package: "phystech", Constraints: &aquatypes.Constraints{RegexMatch: []string{dhcpcdRegExp}}},
	"vncviewer":                            {Vendor: "tightvnc", Package: "tightvnc", Constraints: &aquatypes.Constraints{RegexMatch: []string{vncviewerRegExp}}},
	"Xvnc":                                 {Vendor: "tightvnc", Package: "tightvnc", Constraints: &aquatypes.Constraints{RegexMatch: []string{XvncRegExp}}},
	"pan":                                  {Vendor: "pan", Package: "pan", Constraints: &aquatypes.Constraints{RegexMatch: []string{panRegExp}}},
	"cupsd":                                {Vendor: "cups", Package: "cups", Constraints: &aquatypes.Constraints{RegexMatch: []string{cupsdRegExp}}},
	"printers.cgi":                         {Vendor: "cups", Package: "cups", Constraints: &aquatypes.Constraints{RegexMatch: []string{printerscgiRegExp}}},
	"jobs.cgi":                             {Vendor: "cups", Package: "cups", Constraints: &aquatypes.Constraints{RegexMatch: []string{jobscgiRegExp}}},
	"classes.cgi":                          {Vendor: "cups", Package: "cups", Constraints: &aquatypes.Constraints{RegexMatch: []string{classescgiRegExp}}},
	"help.cgi":                             {Vendor: "cups", Package: "cups", Constraints: &aquatypes.Constraints{RegexMatch: []string{helpcgiRegExp}}},
	"admin.cgi":                            {Vendor: "cups", Package: "cups", Constraints: &aquatypes.Constraints{RegexMatch: []string{admincgiRegExp}}},
	"libcups.so":                           {Vendor: "cups", Package: "cups", Constraints: &aquatypes.Constraints{RegexMatch: []string{libcupssoRegExp, libcupssoRegExp2}}},
	"wpa_":                                 {Vendor: "wpa_supplicant", Package: "wpa_supplicant", Constraints: &aquatypes.Constraints{RegexMatch: []string{wpa_RegExp}}},
	"setfacl":                              {Vendor: "acl", Package: "xfs", Constraints: &aquatypes.Constraints{RegexMatch: []string{setfaclRegExp}}},
	"getfacl":                              {Vendor: "acl", Package: "xfs", Constraints: &aquatypes.Constraints{RegexMatch: []string{getfaclRegExp}}},
	"busybox":                              {Vendor: "busybox", Package: "busybox", Constraints: &aquatypes.Constraints{RegexMatch: []string{busyboxRegExp, busyboxRegExp2}}},
	"bb":                                   {Vendor: "busybox", Package: "busybox", Constraints: &aquatypes.Constraints{RegexMatch: []string{bbRegExp, bbRegExp2}}},
	"mdev":                                 {Vendor: "busybox", Package: "busybox", Constraints: &aquatypes.Constraints{RegexMatch: []string{mdevRegExp, mdevRegExp2}}},
	"dbus-":                                {Vendor: "dbus", Package: "freedesktop", Constraints: &aquatypes.Constraints{RegexMatch: []string{dbusRegExp, dbusRegExp2}}},
	"libdbus-":                             {Vendor: "dbus", Package: "freedesktop", Constraints: &aquatypes.Constraints{RegexMatch: []string{libdbusRegExp}}},
	"ed":                                   {Vendor: "ed", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{edRegExp}}},
	"red":                                  {Vendor: "ed", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{redRegExp}}},
	"eject":                                {Vendor: "eject", Package: "eject", Constraints: &aquatypes.Constraints{RegexMatch: []string{ejectRegExp}}},
	"find":                                 {Vendor: "findutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{findRegExp}}},
	"oldfind":                              {Vendor: "findutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{oldfindRegExp}}},
	"xargs":                                {Vendor: "findutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{xargsRegExp}}},
	"grodvi":                               {Vendor: "groff", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{grodviRegExp}}},
	"grolj4":                               {Vendor: "groff", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{grolj4RegExp}}},
	"grotty":                               {Vendor: "groff", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{grottyRegExp}}},
	"grolbp":                               {Vendor: "groff", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{grolbpRegExp}}},
	"groff":                                {Vendor: "groff", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{groffRegExp}}},
	"sandbox":                              {Vendor: "sandbox", Package: "sandbox", Constraints: &aquatypes.Constraints{RegexMatch: []string{sandboxRegExp}}},
	"libsandbox.so":                        {Vendor: "sandbox", Package: "sandbox", Constraints: &aquatypes.Constraints{RegexMatch: []string{libsandboxsoRegExp}}},
	"texindex":                             {Vendor: "texinfo", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{texindexRegExp}}},
	"install-info":                         {Vendor: "texinfo", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{installinfoRegExp}}},
	"infokey":                              {Vendor: "texinfo", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{infokeyRegExp}}},
	"info":                                 {Vendor: "texinfo", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{infoRegExp}}},
	"tunelp":                               {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{tunelpRegExp, tunelpRegExp2}}},
	"fdformat":                             {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{fdformatRegExp, fdformatRegExp2}}},
	"rtcwake":                              {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{rtcwakeRegExp, rtcwakeRegExp2}}},
	"readprofile":                          {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{readprofileRegExp, readprofileRegExp2}}},
	"ldattach":                             {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{ldattachRegExp, ldattachRegExp2}}},
	"isosize":                              {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{isosizeRegExp, isosizeRegExp2}}},
	"cal":                                  {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{calRegExp, calRegExp2}}},
	"rename":                               {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{renameRegExp, renameRegExp2}}},
	"chrt":                                 {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{chrtRegExp, chrtRegExp2}}},
	"taskset":                              {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{tasksetRegExp, tasksetRegExp2}}},
	"ddate":                                {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{ddateRegExp, ddateRegExp2}}},
	"flock":                                {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{flockRegExp, flockRegExp2}}},
	"script":                               {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{scriptRegExp, scriptRegExp2}}},
	"renice":                               {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{reniceRegExp, reniceRegExp2}}},
	"fdisk":                                {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{fdiskRegExp, fdiskRegExp2}}},
	"fsck.minix":                           {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{fsckminixRegExp, fsckminixRegExp2}}},
	"mkfs":                                 {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{mkfsRegExp, mkfsRegExp2}}},
	"fsck":                                 {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{fsckRegExp, fsckRegExp2}}},
	"sfdisk":                               {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{sfdiskRegExp, sfdiskRegExp2}}},
	"blkid":                                {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{blkidRegExp, blkidRegExp2}}},
	"mkswap":                               {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{mkswapRegExp, mkswapRegExp2}}},
	"mkfs.minix":                           {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{mkfsminixRegExp, mkfsminixRegExp2}}},
	"blockdev":                             {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{blockdevRegExp, blockdevRegExp2}}},
	"swapoff":                              {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{swapoffRegExp, swapoffRegExp2}}},
	"mkfs.bfs":                             {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{mkfsbfsRegExp, mkfsbfsRegExp2}}},
	"mkfs.cramfs":                          {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{mkfscramfsRegExp, mkfscramfsRegExp2}}},
	"cfdisk":                               {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{cfdiskRegExp, cfdiskRegExp2}}},
	"hwclock":                              {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{hwclockRegExp, hwclockRegExp2}}},
	"swapon":                               {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{swaponRegExp, swaponRegExp2}}},
	"switch_root":                          {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{switch_rootRegExp, switch_rootRegExp2}}},
	"grub-install":                         {Vendor: "grub_legacy", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{grubinstallRegExp}}},
	"grub-set-default":                     {Vendor: "grub_legacy", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{grubsetdefaultRegExp}}},
	"grub-terminfo":                        {Vendor: "grub_legacy", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{grubterminfoRegExp}}},
	"grub":                                 {Vendor: "grub_legacy", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{grubRegExp}}},
	"as":                                   {Vendor: "binutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{asRegExp}}},
	"libbfd.so":                            {Vendor: "binutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{libbfdsoRegExp}}},
	"libopcodes":                           {Vendor: "binutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{libopcodesRegExp}}},
	"libbfd-":                              {Vendor: "binutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{libbfdRegExp, libbfdRegExp2}}},
	"lex":                                  {Vendor: "flex", Package: "will_estes", Constraints: &aquatypes.Constraints{RegexMatch: []string{lexRegExp, lexRegExp2}}},
	"flex":                                 {Vendor: "flex", Package: "will_estes", Constraints: &aquatypes.Constraints{RegexMatch: []string{flexRegExp, flexRegExp2}}},
	"protoize":                             {Vendor: "gcc", Package: "gcc", Constraints: &aquatypes.Constraints{RegexMatch: []string{protoizeRegExp, protoizeRegExp2}}},
	"unprotoize":                           {Vendor: "gcc", Package: "gcc", Constraints: &aquatypes.Constraints{RegexMatch: []string{unprotoizeRegExp, unprotoizeRegExp2}}},
	"gdbserver":                            {Vendor: "gdb", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{gdbserverRegExp}}},
	"gettext.sh":                           {Vendor: "gettext", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{gettextshRegExp}}},
	"msgcat":                               {Vendor: "gettext", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{msgcatRegExp}}},
	"ngettext":                             {Vendor: "gettext", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{ngettextRegExp}}},
	"gettextize":                           {Vendor: "gettext", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{gettextizeRegExp}}},
	"libgettext":                           {Vendor: "gettext", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{libgettextRegExp}}},
	"m4":                                   {Vendor: "m4", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{m4RegExp}}},
	"make":                                 {Vendor: "make", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{makeRegExp}}},
	"gmake":                                {Vendor: "make", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{gmakeRegExp}}},
	"lsattr":                               {Vendor: "e2fsprogs", Package: "ext2_filesystems_utilities", Constraints: &aquatypes.Constraints{RegexMatch: []string{lsattrRegExp}}},
	"chattr":                               {Vendor: "e2fsprogs", Package: "ext2_filesystems_utilities", Constraints: &aquatypes.Constraints{RegexMatch: []string{chattrRegExp}}},
	"libext2fs.so":                         {Vendor: "e2fsprogs", Package: "ext2_filesystems_utilities", Constraints: &aquatypes.Constraints{RegexMatch: []string{libext2fssoRegExp, libext2fssoRegExp2}}},
	"fsck.ext2":                            {Vendor: "e2fsprogs", Package: "ext2_filesystems_utilities", Constraints: &aquatypes.Constraints{RegexMatch: []string{fsckext2RegExp}}},
	"e2fsck":                               {Vendor: "e2fsprogs", Package: "ext2_filesystems_utilities", Constraints: &aquatypes.Constraints{RegexMatch: []string{e2fsckRegExp}}},
	"fsck.ext4dev":                         {Vendor: "e2fsprogs", Package: "ext2_filesystems_utilities", Constraints: &aquatypes.Constraints{RegexMatch: []string{fsckext4devRegExp}}},
	"e2image":                              {Vendor: "e2fsprogs", Package: "ext2_filesystems_utilities", Constraints: &aquatypes.Constraints{RegexMatch: []string{e2imageRegExp}}},
	"mkfs.ext3":                            {Vendor: "e2fsprogs", Package: "ext2_filesystems_utilities", Constraints: &aquatypes.Constraints{RegexMatch: []string{mkfsext3RegExp}}},
	"mke2fs":                               {Vendor: "e2fsprogs", Package: "ext2_filesystems_utilities", Constraints: &aquatypes.Constraints{RegexMatch: []string{mke2fsRegExp}}},
	"e2label":                              {Vendor: "e2fsprogs", Package: "ext2_filesystems_utilities", Constraints: &aquatypes.Constraints{RegexMatch: []string{e2labelRegExp}}},
	"dumpe2fs":                             {Vendor: "e2fsprogs", Package: "ext2_filesystems_utilities", Constraints: &aquatypes.Constraints{RegexMatch: []string{dumpe2fsRegExp}}},
	"fsck.ext4":                            {Vendor: "e2fsprogs", Package: "ext2_filesystems_utilities", Constraints: &aquatypes.Constraints{RegexMatch: []string{fsckext4RegExp}}},
	"tune2fs":                              {Vendor: "e2fsprogs", Package: "ext2_filesystems_utilities", Constraints: &aquatypes.Constraints{RegexMatch: []string{tune2fsRegExp}}},
	"debugfs":                              {Vendor: "e2fsprogs", Package: "ext2_filesystems_utilities", Constraints: &aquatypes.Constraints{RegexMatch: []string{debugfsRegExp}}},
	"mkfs.ext2":                            {Vendor: "e2fsprogs", Package: "ext2_filesystems_utilities", Constraints: &aquatypes.Constraints{RegexMatch: []string{mkfsext2RegExp}}},
	"fsck.ext3":                            {Vendor: "e2fsprogs", Package: "ext2_filesystems_utilities", Constraints: &aquatypes.Constraints{RegexMatch: []string{fsckext3RegExp}}},
	"mkfs.ext4dev":                         {Vendor: "e2fsprogs", Package: "ext2_filesystems_utilities", Constraints: &aquatypes.Constraints{RegexMatch: []string{mkfsext4devRegExp}}},
	"mkfs.ext4":                            {Vendor: "e2fsprogs", Package: "ext2_filesystems_utilities", Constraints: &aquatypes.Constraints{RegexMatch: []string{mkfsext4RegExp}}},
	"resize2fs":                            {Vendor: "e2fsprogs", Package: "ext2_filesystems_utilities", Constraints: &aquatypes.Constraints{RegexMatch: []string{resize2fsRegExp}}},
	"libfuse.so":                           {Vendor: "fuse", Package: "fuse", Constraints: &aquatypes.Constraints{RegexMatch: []string{libfusesoRegExp}}},
	"iconvconfig":                          {Vendor: "glibc", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{iconvconfigRegExp}}},
	"rpcinfo":                              {Vendor: "glibc", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{rpcinfoRegExp}}},
	"nscd":                                 {Vendor: "glibc", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{nscdRegExp}}},
	"lddlibc4":                             {Vendor: "glibc", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{lddlibc4RegExp}}},
	"iconv":                                {Vendor: "glibc", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{iconvRegExp}}},
	"locale":                               {Vendor: "glibc", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{localeRegExp}}},
	"rpcgen":                               {Vendor: "glibc", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{rpcgenRegExp}}},
	"getconf":                              {Vendor: "glibc", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{getconfRegExp}}},
	"getent":                               {Vendor: "glibc", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{getentRegExp}}},
	"localedef":                            {Vendor: "glibc", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{localedefRegExp}}},
	"sprof":                                {Vendor: "glibc", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{sprofRegExp}}},
	"libthread_db":                         {Vendor: "glibc", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{libthread_dbRegExp}}},
	"ldconfig":                             {Vendor: "glibc", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{ldconfigRegExp}}},
	"libpthread.so":                        {Vendor: "glibc", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{libpthreadsoRegExp}}},
	"libpthread-":                          {Vendor: "glibc", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{libpthreadRegExp}}},
	"gencat":                               {Vendor: "glibc", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{gencatRegExp}}},
	"pcprofiledump":                        {Vendor: "glibc", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{pcprofiledumpRegExp}}},
	"sln":                                  {Vendor: "glibc", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{slnRegExp}}},
	"pam_cracklib.so":                      {Vendor: "pam", Package: "pam", Constraints: &aquatypes.Constraints{RegexMatch: []string{pam_cracklibsoRegExp}}},
	"pam_xauth.so":                         {Vendor: "pam", Package: "pam", Constraints: &aquatypes.Constraints{RegexMatch: []string{pam_xauthsoRegExp}}},
	"libz.so":                              {Vendor: "zlib", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{libzsoRegExp}}},
	"pango-":                               {Vendor: "pango", Package: "pango", Constraints: &aquatypes.Constraints{RegexMatch: []string{pangoRegExp}}},
	"libpango-":                            {Vendor: "pango", Package: "pango", Constraints: &aquatypes.Constraints{RegexMatch: []string{libpangoRegExp}}},
	"xscreensaver":                         {Vendor: "xscreensaver", Package: "xscreensaver", Constraints: &aquatypes.Constraints{RegexMatch: []string{xscreensaverRegExp}}},
	"id3v2":                                {Vendor: "id3v2", Package: "id3v2", Constraints: &aquatypes.Constraints{RegexMatch: []string{id3v2RegExp}}},
	"libid3":                               {Vendor: "id3lib", Package: "id3lib", Constraints: &aquatypes.Constraints{RegexMatch: []string{libid3RegExp}}},
	"id3info":                              {Vendor: "id3lib", Package: "id3lib", Constraints: &aquatypes.Constraints{RegexMatch: []string{id3infoRegExp}}},
	"id3cp":                                {Vendor: "id3lib", Package: "id3lib", Constraints: &aquatypes.Constraints{RegexMatch: []string{id3cpRegExp}}},
	"neon-config":                          {Vendor: "neon", Package: "webdav", Constraints: &aquatypes.Constraints{RegexMatch: []string{neonconfigRegExp}}},
	"transmission":                         {Vendor: "transmission", Package: "transmissionbt", Constraints: &aquatypes.Constraints{RegexMatch: []string{transmissionRegExp}}},
	"acpi":                                 {Vendor: "acpi", Package: "tim_hockin", Constraints: &aquatypes.Constraints{RegexMatch: []string{acpiRegExp}}},
	"libbrltty":                            {Vendor: "brltty", Package: "mielke", Constraints: &aquatypes.Constraints{RegexMatch: []string{libbrlttyRegExp}}},
	"cat":                                  {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{catRegExp}}},
	"chgrp":                                {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{chgrpRegExp}}},
	"chmod":                                {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{chmodRegExp}}},
	"chown":                                {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{chownRegExp}}},
	"cp":                                   {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{cpRegExp}}},
	"date":                                 {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{dateRegExp}}},
	"dd":                                   {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{ddRegExp}}},
	"dir":                                  {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{dirRegExp}}},
	"echo":                                 {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{echoRegExp}}},
	"false":                                {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{falseRegExp}}},
	"ln":                                   {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{lnRegExp}}},
	"ls":                                   {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{lsRegExp}}},
	"mkdir":                                {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{mkdirRegExp}}},
	"mknod":                                {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{mknodRegExp}}},
	"mv":                                   {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{mvRegExp}}},
	"pwd":                                  {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{pwdRegExp}}},
	"readlink":                             {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{readlinkRegExp}}},
	"rm":                                   {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{rmRegExp}}},
	"rmdir":                                {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{rmdirRegExp}}},
	"vdir":                                 {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{vdirRegExp}}},
	"sync":                                 {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{syncRegExp}}},
	"touch":                                {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{touchRegExp, touchRegExp2}}},
	"true":                                 {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{trueRegExp}}},
	"uname":                                {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{unameRegExp}}},
	"mktemp":                               {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{mktempRegExp}}},
	"install":                              {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{installRegExp}}},
	"hostid":                               {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{hostidRegExp}}},
	"nice":                                 {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{niceRegExp}}},
	"who":                                  {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{whoRegExp}}},
	"users":                                {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{usersRegExp}}},
	"pinky":                                {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{pinkyRegExp}}},
	"chcon":                                {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{chconRegExp}}},
	"dircolors":                            {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{dircolorsRegExp}}},
	"du":                                   {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{duRegExp}}},
	"link":                                 {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{linkRegExp}}},
	"mkfifo":                               {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{mkfifoRegExp}}},
	"nohup":                                {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{nohupRegExp}}},
	"shred":                                {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{shredRegExp}}},
	"stat":                                 {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{statRegExp}}},
	"unlink":                               {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{unlinkRegExp}}},
	"cksum":                                {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{cksumRegExp}}},
	"comm":                                 {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{commRegExp}}},
	"csplit":                               {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{csplitRegExp}}},
	"cut":                                  {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{cutRegExp}}},
	"expand":                               {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{expandRegExp}}},
	"fmt":                                  {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{fmtRegExp}}},
	"fold":                                 {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{foldRegExp}}},
	"head":                                 {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{headRegExp}}},
	"join":                                 {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{joinRegExp}}},
	"groups":                               {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{groupsRegExp}}},
	"md5sum":                               {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{md5sumRegExp}}},
	"nl":                                   {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{nlRegExp}}},
	"od":                                   {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{odRegExp}}},
	"paste":                                {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{pasteRegExp}}},
	"pr":                                   {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{prRegExp}}},
	"ptx":                                  {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{ptxRegExp}}},
	"sha1sum":                              {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{sha1sumRegExp}}},
	"sha224sum":                            {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{sha224sumRegExp}}},
	"sha256sum":                            {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{sha256sumRegExp}}},
	"sha384sum":                            {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{sha384sumRegExp}}},
	"sha512sum":                            {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{sha512sumRegExp}}},
	"shuf":                                 {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{shufRegExp}}},
	"split":                                {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{splitRegExp}}},
	"tac":                                  {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{tacRegExp}}},
	"tail":                                 {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{tailRegExp}}},
	"tr":                                   {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{trRegExp}}},
	"tsort":                                {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{tsortRegExp}}},
	"unexpand":                             {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{unexpandRegExp}}},
	"uniq":                                 {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{uniqRegExp}}},
	"wc":                                   {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{wcRegExp}}},
	"basename":                             {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{basenameRegExp}}},
	"env":                                  {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{envRegExp}}},
	"expr":                                 {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{exprRegExp}}},
	"factor":                               {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{factorRegExp}}},
	"id":                                   {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{idRegExp}}},
	"logname":                              {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{lognameRegExp}}},
	"pathchk":                              {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{pathchkRegExp}}},
	"printenv":                             {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{printenvRegExp}}},
	"printf":                               {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{printfRegExp}}},
	"runcon":                               {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{runconRegExp}}},
	"tee":                                  {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{teeRegExp}}},
	"truncate":                             {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{truncateRegExp}}},
	"tty":                                  {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{ttyRegExp}}},
	"whoami":                               {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{whoamiRegExp}}},
	"yes":                                  {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{yesRegExp}}},
	"base64":                               {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{base64RegExp}}},
	"arch":                                 {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{archRegExp}}},
	"chroot":                               {Vendor: "coreutils", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{chrootRegExp}}},
	"mt-gnu":                               {Vendor: "cpio", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{mtgnuRegExp}}},
	"libevolution":                         {Vendor: "evolution", Package: "gnome", Constraints: &aquatypes.Constraints{RegexMatch: []string{libevolutionRegExp}}},
	"evolution":                            {Vendor: "evolution", Package: "gnome", Constraints: &aquatypes.Constraints{RegexMatch: []string{evolutionRegExp}}},
	"gdb":                                  {Vendor: "gdb", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{gdbRegExp}}},
	"gdm-binary":                           {Vendor: "gdm", Package: "gnome", Constraints: &aquatypes.Constraints{RegexMatch: []string{gdmbinaryRegExp}}},
	"gdmflexiserver":                       {Vendor: "gdm", Package: "gnome", Constraints: &aquatypes.Constraints{RegexMatch: []string{gdmflexiserverRegExp}}},
	"gpgsplit":                             {Vendor: "gnupg", Package: "gnupg", Constraints: &aquatypes.Constraints{RegexMatch: []string{gpgsplitRegExp}}},
	"gpg-zip":                              {Vendor: "gnupg", Package: "gnupg", Constraints: &aquatypes.Constraints{RegexMatch: []string{gpgzipRegExp}}},
	"hp-mkuri":                             {Vendor: "hplip", Package: "hp", Constraints: &aquatypes.Constraints{RegexMatch: []string{hpmkuriRegExp}}},
	"iptables":                             {Vendor: "iptables", Package: "netfilter_core_team", Constraints: &aquatypes.Constraints{RegexMatch: []string{iptablesRegExp, iptablesRegExp2}}},
	"ip6tables":                            {Vendor: "iptables", Package: "netfilter_core_team", Constraints: &aquatypes.Constraints{RegexMatch: []string{ip6tablesRegExp}}},
	"ip6tables-restore":                    {Vendor: "iptables", Package: "netfilter_core_team", Constraints: &aquatypes.Constraints{RegexMatch: []string{ip6tablesrestoreRegExp}}},
	"ip6tables-save":                       {Vendor: "iptables", Package: "netfilter_core_team", Constraints: &aquatypes.Constraints{RegexMatch: []string{ip6tablessaveRegExp}}},
	"lftp":                                 {Vendor: "lftp", Package: "alexander_v._lukyanov", Constraints: &aquatypes.Constraints{RegexMatch: []string{lftpRegExp}}},
	"ltrace":                               {Vendor: "ltrace", Package: "juan_cespedes", Constraints: &aquatypes.Constraints{RegexMatch: []string{ltraceRegExp}}},
	"libaudioscrobbler.so":                 {Vendor: "rhythmbox", Package: "gnome", Constraints: &aquatypes.Constraints{RegexMatch: []string{libaudioscrobblersoRegExp}}},
	"libdaap.so":                           {Vendor: "rhythmbox", Package: "gnome", Constraints: &aquatypes.Constraints{RegexMatch: []string{libdaapsoRegExp}}},
	"libmtpdevice.so":                      {Vendor: "rhythmbox", Package: "gnome", Constraints: &aquatypes.Constraints{RegexMatch: []string{libmtpdevicesoRegExp}}},
	"libfmradio.so":                        {Vendor: "rhythmbox", Package: "gnome", Constraints: &aquatypes.Constraints{RegexMatch: []string{libfmradiosoRegExp}}},
	"rhythmbox":                            {Vendor: "rhythmbox", Package: "gnome", Constraints: &aquatypes.Constraints{RegexMatch: []string{rhythmboxRegExp}}},
	"rsync":                                {Vendor: "rsync", Package: "samba", Constraints: &aquatypes.Constraints{RegexMatch: []string{rsyncRegExp}}},
	"imuxsock.so":                          {Vendor: "rsyslog", Package: "rsyslog", Constraints: &aquatypes.Constraints{RegexMatch: []string{imuxsocksoRegExp, imuxsocksoRegExp2}}},
	"ommail.so":                            {Vendor: "rsyslogd", Package: "rsyslog", Constraints: &aquatypes.Constraints{RegexMatch: []string{ommailsoRegExp, ommailsoRegExp2}}},
	"sudo":                                 {Vendor: "sudo", Package: "todd_miller", Constraints: &aquatypes.Constraints{RegexMatch: []string{sudoRegExp}}},
	"visudo":                               {Vendor: "sudo", Package: "todd_miller", Constraints: &aquatypes.Constraints{RegexMatch: []string{visudoRegExp}}},
	"vinagre":                              {Vendor: "vinagre", Package: "gnome", Constraints: &aquatypes.Constraints{RegexMatch: []string{vinagreRegExp}}},
	"w3m":                                  {Vendor: "w3m", Package: "w3m", Constraints: &aquatypes.Constraints{RegexMatch: []string{w3mRegExp}}},
	"xinput":                               {Vendor: "xinput", Package: "x.org", Constraints: &aquatypes.Constraints{RegexMatch: []string{xinputRegExp, xinputRegExp2}}},
	"xsane":                                {Vendor: "xsane", Package: "oliver_rauch", Constraints: &aquatypes.Constraints{RegexMatch: []string{xsaneRegExp}}},
	"xml":                                  {Vendor: "command_line_xml_toolkit", Package: "xmlstarlet", Constraints: &aquatypes.Constraints{RegexMatch: []string{xmlRegExp}}},
	"xmlstarlet":                           {Vendor: "command_line_xml_toolkit", Package: "xmlstarlet", Constraints: &aquatypes.Constraints{RegexMatch: []string{xmlstarletRegExp}}},
	"ndisasm":                              {Vendor: "nasm", Package: "nasm", Constraints: &aquatypes.Constraints{RegexMatch: []string{ndisasmRegExp, ndisasmRegExp2}}},
	"libtasn1.so":                          {Vendor: "libtasn1", Package: "free_software_foundation_inc", Constraints: &aquatypes.Constraints{RegexMatch: []string{libtasn1soRegExp}}},
	"asn1":                                 {Vendor: "libtasn1", Package: "free_software_foundation_inc", Constraints: &aquatypes.Constraints{RegexMatch: []string{asn1RegExp}}},
	"libgconf-2.so":                        {Vendor: "gconf", Package: "gnome", Constraints: &aquatypes.Constraints{RegexMatch: []string{libgconf2soRegExp}}},
	"gconftool-2":                          {Vendor: "gconf", Package: "gnome", Constraints: &aquatypes.Constraints{RegexMatch: []string{gconftool2RegExp}}},
	"gdm":                                  {Vendor: "gdm", Package: "gnome", Constraints: &aquatypes.Constraints{RegexMatch: []string{gdmRegExp}}},
	"libgtop-2.0.so":                       {Vendor: "libgtop_daemon", Package: "gnome", Constraints: &aquatypes.Constraints{RegexMatch: []string{libgtop20soRegExp, libgtop20soRegExp2}}},
	"formail":                              {Vendor: "procmail", Package: "procmail", Constraints: &aquatypes.Constraints{RegexMatch: []string{formailRegExp}}},
	"postalias":                            {Vendor: "postfix", Package: "postfix", Constraints: &aquatypes.Constraints{RegexMatch: []string{postaliasRegExp}}},
	"postcat":                              {Vendor: "postfix", Package: "postfix", Constraints: &aquatypes.Constraints{RegexMatch: []string{postcatRegExp}}},
	"postfix":                              {Vendor: "postfix", Package: "postfix", Constraints: &aquatypes.Constraints{RegexMatch: []string{postfixRegExp}}},
	"postkick":                             {Vendor: "postfix", Package: "postfix", Constraints: &aquatypes.Constraints{RegexMatch: []string{postkickRegExp}}},
	"postlog":                              {Vendor: "postfix", Package: "postfix", Constraints: &aquatypes.Constraints{RegexMatch: []string{postlogRegExp}}},
	"postmap":                              {Vendor: "postfix", Package: "postfix", Constraints: &aquatypes.Constraints{RegexMatch: []string{postmapRegExp}}},
	"postmulti":                            {Vendor: "postfix", Package: "postfix", Constraints: &aquatypes.Constraints{RegexMatch: []string{postmultiRegExp}}},
	"postsuper":                            {Vendor: "postfix", Package: "postfix", Constraints: &aquatypes.Constraints{RegexMatch: []string{postsuperRegExp}}},
	"postdrop":                             {Vendor: "postfix", Package: "postfix", Constraints: &aquatypes.Constraints{RegexMatch: []string{postdropRegExp}}},
	"postqueue":                            {Vendor: "postfix", Package: "postfix", Constraints: &aquatypes.Constraints{RegexMatch: []string{postqueueRegExp}}},
	"faad":                                 {Vendor: "faad", Package: "audiocoding", Constraints: &aquatypes.Constraints{RegexMatch: []string{faadRegExp}}},
	"imlib2-config":                        {Vendor: "imlib2", Package: "enlightenment", Constraints: &aquatypes.Constraints{RegexMatch: []string{imlib2configRegExp}}},
	"xine":                                 {Vendor: "xine-ui", Package: "xine", Constraints: &aquatypes.Constraints{RegexMatch: []string{xineRegExp}}},
	"fbxine":                               {Vendor: "xine-ui", Package: "xine", Constraints: &aquatypes.Constraints{RegexMatch: []string{fbxineRegExp}}},
	"nfsstat":                              {Vendor: "nfs-utils", Package: "nfs", Constraints: &aquatypes.Constraints{RegexMatch: []string{nfsstatRegExp}}},
	"rpc.mountd":                           {Vendor: "nfs-utils", Package: "nfs", Constraints: &aquatypes.Constraints{RegexMatch: []string{rpcmountdRegExp}}},
	"showmount":                            {Vendor: "nfs-utils", Package: "nfs", Constraints: &aquatypes.Constraints{RegexMatch: []string{showmountRegExp}}},
	"rpc.statd":                            {Vendor: "nfs-utils", Package: "nfs", Constraints: &aquatypes.Constraints{RegexMatch: []string{rpcstatdRegExp}}},
	"irssi":                                {Vendor: "irssi", Package: "irssi", Constraints: &aquatypes.Constraints{RegexMatch: []string{irssiRegExp}}},
	"apt":                                  {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{aptRegExp, aptRegExp2}}},
	"idlj":                                 {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{idljRegExp, idljRegExp2}}},
	"keytool":                              {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{keytoolRegExp, keytoolRegExp2, keytoolRegExp3, keytoolRegExp4}}},
	"jarsigner":                            {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{jarsignerRegExp, jarsignerRegExp2}}},
	"policytool":                           {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{policytoolRegExp, policytoolRegExp2, policytoolRegExp3, policytoolRegExp4}}},
	"jar":                                  {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{jarRegExp, jarRegExp2}}},
	"xjc":                                  {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{xjcRegExp, xjcRegExp2}}},
	"schemagen":                            {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{schemagenRegExp, schemagenRegExp2}}},
	"wsgen":                                {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{wsgenRegExp, wsgenRegExp2}}},
	"wsimport":                             {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{wsimportRegExp, wsimportRegExp2}}},
	"appletviewer":                         {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{appletviewerRegExp, appletviewerRegExp2}}},
	"rmic":                                 {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{rmicRegExp, rmicRegExp2}}},
	"rmiregistry":                          {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{rmiregistryRegExp, rmiregistryRegExp2, rmiregistryRegExp3, rmiregistryRegExp4}}},
	"rmid":                                 {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{rmidRegExp, rmidRegExp2, rmidRegExp3, rmidRegExp4}}},
	"native2ascii":                         {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{native2asciiRegExp, native2asciiRegExp2}}},
	"serialver":                            {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{serialverRegExp, serialverRegExp2}}},
	"jps":                                  {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{jpsRegExp, jpsRegExp2}}},
	"jstat":                                {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{jstatRegExp, jstatRegExp2}}},
	"jstatd":                               {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{jstatdRegExp, jstatdRegExp2}}},
	"jsadebugd":                            {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{jsadebugdRegExp, jsadebugdRegExp2}}},
	"jstack":                               {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{jstackRegExp, jstackRegExp2}}},
	"jmap":                                 {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{jmapRegExp, jmapRegExp2}}},
	"jinfo":                                {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{jinfoRegExp, jinfoRegExp2}}},
	"jconsole":                             {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{jconsoleRegExp, jconsoleRegExp2}}},
	"jrunscript":                           {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{jrunscriptRegExp, jrunscriptRegExp2}}},
	"jhat":                                 {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{jhatRegExp, jhatRegExp2}}},
	"tnameserv":                            {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{tnameservRegExp, tnameservRegExp2, tnameservRegExp3, tnameservRegExp4}}},
	"orbd":                                 {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{orbdRegExp, orbdRegExp2, orbdRegExp3, orbdRegExp4}}},
	"servertool":                           {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{servertoolRegExp, servertoolRegExp2, servertoolRegExp3, servertoolRegExp4}}},
	"pack200":                              {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{pack200RegExp, pack200RegExp2, pack200RegExp3, pack200RegExp4}}},
	"extcheck":                             {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{extcheckRegExp, extcheckRegExp2}}},
	"jdb":                                  {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{jdbRegExp, jdbRegExp2}}},
	"java_vm":                              {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{java_vmRegExp, java_vmRegExp2}}},
	"libjava.so":                           {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{libjavasoRegExp, libjavasoRegExp2}}},
	"libjavaplugin_nscp_gcc29.so":          {Vendor: "jdk", Package: "sun", Constraints: &aquatypes.Constraints{RegexMatch: []string{libjavaplugin_nscp_gcc29soRegExp, libjavaplugin_nscp_gcc29soRegExp2}}},
	"mod_ssl.so":                           {Vendor: "http_server", Package: "apache", Constraints: &aquatypes.Constraints{RegexMatch: []string{mod_sslsoRegExp}}},
	"libvirtd":                             {Vendor: "libvirt", Package: "libvirt", Constraints: &aquatypes.Constraints{RegexMatch: []string{libvirtdRegExp}}},
	"libvirt.so":                           {Vendor: "libvirt", Package: "libvirt", Constraints: &aquatypes.Constraints{RegexMatch: []string{libvirtsoRegExp}}},
	"libvirt-qemu.so":                      {Vendor: "libvirt", Package: "libvirt", Constraints: &aquatypes.Constraints{RegexMatch: []string{libvirtqemusoRegExp}}},
	"dnsmasq":                              {Vendor: "dnsmasq", Package: "thekelleys", Constraints: &aquatypes.Constraints{RegexMatch: []string{dnsmasqRegExp}}},
	"gnutls":                               {Vendor: "gnutls", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{gnutlsRegExp}}},
	"psktool":                              {Vendor: "gnutls", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{psktoolRegExp}}},
	"srptool":                              {Vendor: "gnutls", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{srptoolRegExp}}},
	"certtool":                             {Vendor: "gnutls", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{certtoolRegExp}}},
	"libgnutls-extra.so":                   {Vendor: "gnutls", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{libgnutlsextrasoRegExp}}},
	"libgnutls.so":                         {Vendor: "gnutls", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{libgnutlssoRegExp}}},
	"makeinfo":                             {Vendor: "texinfo", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{makeinfoRegExp}}},
	"libtool":                              {Vendor: "libtool", Package: "gnu", Constraints: &aquatypes.Constraints{RegexMatch: []string{libtoolRegExp}}},
	"links":                                {Vendor: "links", Package: "links", Constraints: &aquatypes.Constraints{RegexMatch: []string{linksRegExp, linksRegExp2}}},
	"_cairo.so":                            {Vendor: "cairo", Package: "redhat", Constraints: &aquatypes.Constraints{RegexMatch: []string{_cairosoRegExp}}},
	"resolve_stack_dump":                   {Vendor: "mysql", Package: "mysql", Constraints: &aquatypes.Constraints{RegexMatch: []string{resolve_stack_dumpRegExp}}},
	"mysql":                                {Vendor: "mysql", Package: "mysql", Constraints: &aquatypes.Constraints{RegexMatch: []string{mysqlRegExp}}},
	"libphp5.so":                           {Vendor: "php", Package: "php", Constraints: &aquatypes.Constraints{RegexMatch: []string{libphp5soRegExp}}},
	"php":                                  {Vendor: "php", Package: "php", Constraints: &aquatypes.Constraints{RegexMatch: []string{phpRegExp}}},
	"libmcrypt.so":                         {Vendor: "libmcrypt", Package: "mcrypt", Constraints: &aquatypes.Constraints{RegexMatch: []string{libmcryptsoRegExp}}},
	"libmount.so":                          {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{libmountsoRegExp}}},
	"libblkid.so":                          {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{libblkidsoRegExp}}},
	"umount":                               {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{umountRegExp}}},
	"mount":                                {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{mountRegExp}}},
	"findmnt":                              {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{findmntRegExp}}},
	"aureport":                             {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{aureportRegExp}}},
	"ausearch":                             {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{ausearchRegExp}}},
	"auditd":                               {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{auditdRegExp}}},
	"auditctl":                             {Vendor: "util-linux", Package: "linux", Constraints: &aquatypes.Constraints{RegexMatch: []string{auditctlRegExp}}},
	"libmysqlclient_r.so":                  {Vendor: "mysql", Package: "mysql", Constraints: &aquatypes.Constraints{RegexMatch: []string{libmysqlclient_rsoRegExp}}},
	"libmysqlclient.so":                    {Vendor: "mysql", Package: "mysql", Constraints: &aquatypes.Constraints{RegexMatch: []string{libmysqlclientsoRegExp}}},
	"bsdcpio":                              {Vendor: "libarchive", Package: "freebsd", Constraints: &aquatypes.Constraints{RegexMatch: []string{bsdcpioRegExp}}},
	"bsdtar":                               {Vendor: "libarchive", Package: "freebsd", Constraints: &aquatypes.Constraints{RegexMatch: []string{bsdtarRegExp}}},
	"libarchive.so":                        {Vendor: "libarchive", Package: "freebsd", Constraints: &aquatypes.Constraints{RegexMatch: []string{libarchivesoRegExp}}},
	"named":                                {Vendor: "bind", Package: "isc", Constraints: &aquatypes.Constraints{RegexMatch: []string{namedRegExp}}},
	"libisc.so":                            {Vendor: "bind", Package: "isc", Constraints: &aquatypes.Constraints{RegexMatch: []string{libiscsoRegExp}}},
	"libisccfg.so":                         {Vendor: "bind", Package: "isc", Constraints: &aquatypes.Constraints{RegexMatch: []string{libisccfgsoRegExp}}},
	"libbind9.so":                          {Vendor: "bind", Package: "isc", Constraints: &aquatypes.Constraints{RegexMatch: []string{libbind9soRegExp}}},
	"liblwres.so":                          {Vendor: "bind", Package: "isc", Constraints: &aquatypes.Constraints{RegexMatch: []string{liblwressoRegExp}}},
	"courier-imapd":                        {Vendor: "courier-imap", Package: "double_precision_incorporated", Constraints: &aquatypes.Constraints{RegexMatch: []string{courierimapdRegExp}}},
	"newrole":                              {Vendor: "policycoreutils", Package: "redhat", Constraints: &aquatypes.Constraints{RegexMatch: []string{newroleRegExp}}},
	"secon":                                {Vendor: "policycoreutils", Package: "redhat", Constraints: &aquatypes.Constraints{RegexMatch: []string{seconRegExp}}},
	"lighttpd":                             {Vendor: "lighttpd", Package: "lighttpd", Constraints: &aquatypes.Constraints{RegexMatch: []string{lighttpdRegExp}}},
	"mod_dirlisting.so":                    {Vendor: "lighttpd", Package: "lighttpd", Constraints: &aquatypes.Constraints{RegexMatch: []string{moddirlistingsoRegExp}}},
	"mod_cgi.so":                           {Vendor: "lighttpd", Package: "lighttpd", Constraints: &aquatypes.Constraints{RegexMatch: []string{mod_cgisoRegExp}}},
	"mod_scgi.so":                          {Vendor: "lighttpd", Package: "lighttpd", Constraints: &aquatypes.Constraints{RegexMatch: []string{mod_scgisoRegExp}}},
	"mod_fastcgi.so":                       {Vendor: "lighttpd", Package: "lighttpd", Constraints: &aquatypes.Constraints{RegexMatch: []string{mod_fastcgisoRegExp}}},
	"mod_ssi.so":                           {Vendor: "lighttpd", Package: "lighttpd", Constraints: &aquatypes.Constraints{RegexMatch: []string{mod_ssisoRegExp}}},
}

//<<<<<<< HEAD
//var ExesInfo = map[string]ExeInfo{
//	"bash":                                 {"bash", "gnu", []*regexp.Regexp{bashRegExp, bashRegExp2}},
//	"wget":                                 {"wget", "gnu", []*regexp.Regexp{wgetRegExp, wgetRegExp2, wgetRegExp3}},
//	"7za":                                  {"p7zip", "7-zip", []*regexp.Regexp{zaRegExp}},
//	"node":                                 {"node.js", "nodejs", []*regexp.Regexp{nodeRegExp, nodeRegExp2, nodeJSRegExp}},
//	"version.sh":                           {"tomcat", "apache", []*regexp.Regexp{tomcatRegExp}},
//	"perl":                                 {"perl", "perl", []*regexp.Regexp{perlRegExp2, perlRegExp4, perlRegExp, perlRegExp3}},
//	"perlivp":                              {"perl", "perl", []*regexp.Regexp{perlivpRegExp}},
//	"java":                                 {"jre", "sun", []*regexp.Regexp{javaRegExp, javaJDKRegExp, javaRegOSExp}},
//	"gdlib-config":                         {"gd_graphics_library", "libgd", []*regexp.Regexp{gdlibconfigRegExp}},
//	"fetchmail":                            {"fetchmail", "eric_raymond", []*regexp.Regexp{fetchmailRegExp}},
//	"nano":                                 {"nano", "gnu", []*regexp.Regexp{nanoRegExp}},
//	"rnano":                                {"nano", "gnu", []*regexp.Regexp{rnanoRegExp}},
//	"wireshark":                            {"wireshark", "wireshark", []*regexp.Regexp{wiresharkRegExp}},
//	"libxine.so":                           {"xine-lib", "xine", []*regexp.Regexp{libxinesoRegExp, gmimeconfigRegExp2}},
//	"libMagickCore.so":                     {"imagemagick", "imagemagick", []*regexp.Regexp{libMagickCoresoRegExp, libMagickCoresoRegExp2, libMagickCoresoRegExp3}},
//	"libruby.so":                           {"ruby", "ruby-lang", []*regexp.Regexp{librubysoRegExp}},
//	"libflashplayer.so":                    {"flash_player", "adobe", []*regexp.Regexp{libflashplayersoRegExp}}
//	"openssl":                              {"openssl", "openssl", []*regexp.Regexp{opensslRegExp}},
//	"gettext":                              {"gettext", "gnu", []*regexp.Regexp{gettextRegExp}},
//	"envsubst":                             {"gettext", "gnu", []*regexp.Regexp{envsubstRegExp}},
//	"msgcmp":                               {"gettext", "gnu", []*regexp.Regexp{msgcmpRegExp}},
//	"msgfmt":                               {"gettext", "gnu", []*regexp.Regexp{msgfmtRegExp}},
//	"msgmerge":                             {"gettext", "gnu", []*regexp.Regexp{msgmergeRegExp}},
//	"msgunfmt":                             {"gettext", "gnu", []*regexp.Regexp{msgunfmtRegExp}},
//	"xgettext":                             {"gettext", "gnu", []*regexp.Regexp{xgettextRegExp}},
//	"msgattrib":                            {"gettext", "gnu", []*regexp.Regexp{msgattribRegExp}},
//	"msgcomm":                              {"gettext", "gnu", []*regexp.Regexp{msgcommRegExp}},
//	"msgconv":                              {"gettext", "gnu", []*regexp.Regexp{msgconvRegExp}},
//	"msgen":                                {"gettext", "gnu", []*regexp.Regexp{msgenRegExp}},
//	"msgexec":                              {"gettext", "gnu", []*regexp.Regexp{msgexecRegExp}},
//	"msgfilter":                            {"gettext", "gnu", []*regexp.Regexp{msgfilterRegExp}},
//	"msggrep":                              {"gettext", "gnu", []*regexp.Regexp{msggrepRegExp}},
//	"msginit":                              {"gettext", "gnu", []*regexp.Regexp{msginitRegExp}},
//	"msguniq":                              {"gettext", "gnu", []*regexp.Regexp{msguniqRegExp}},
//	"syslog-ng":                            {"syslog-ng_open_source_edition", "balabit", []*regexp.Regexp{syslogngRegExp}},
//	"sar":                                  {"sysstat", "sysstat", []*regexp.Regexp{sarRegExp}},
//	"bzip2":                                {"bzip2", "bzip", []*regexp.Regexp{bzip2RegExp}},
//	"cabextract":                           {"cabextract", "cabextract", []*regexp.Regexp{cabextractRegExp}},
//	"cpio":                                 {"cpio", "gnu", []*regexp.Regexp{cpioRegExp}},
//	"gzip":                                 {"gzip", "gnu", []*regexp.Regexp{gzipRegExp}},
//	"gunzip":                               {"gzip", "gnu", []*regexp.Regexp{gunzipRegExp}},
//	"uncompress":                           {"gzip", "gnu", []*regexp.Regexp{uncompressRegExp}},
//	"zcat":                                 {"gzip", "gnu", []*regexp.Regexp{zcatRegExp}},
//	"gzexe":                                {"gzip", "gnu", []*regexp.Regexp{gzexeRegExp}},
//	"zless":                                {"gzip", "gnu", []*regexp.Regexp{zlessRegExp}},
//	"zmore":                                {"gzip", "gnu", []*regexp.Regexp{zmoreRegExp}},
//	"znew":                                 {"gzip", "gnu", []*regexp.Regexp{znewRegExp}},
//	"zcmp":                                 {"gzip", "gnu", []*regexp.Regexp{zcmpRegExp}},
//	"zgrep":                                {"gzip", "gnu", []*regexp.Regexp{zgrepRegExp}},
//	"zforce":                               {"gzip", "gnu", []*regexp.Regexp{zforceRegExp}},
//	"zdiff":                                {"gzip", "gnu", []*regexp.Regexp{zdiffRegExp}},
//	"shar":                                 {"sharutils", "gnu", []*regexp.Regexp{sharRegExp}},
//	"tar":                                  {"tar", "gnu", []*regexp.Regexp{tarRegExp, tarRegExp2}},
//	"rmt":                                  {"tar", "gnu", []*regexp.Regexp{rmtRegExp}},
//	"cdrdao":                               {"cdrdao", "andreas_mueller", []*regexp.Regexp{cdrdaoRegExp, cdrdaoRegExp2}},
//	"mkisofs":                              {"cdrecord", "cdrtools", []*regexp.Regexp{mkisofsRegExp, mkisofsRegExp2, mkisofsRegExp3}},
//	"gpg":                                  {"gnupg", "gnupg", []*regexp.Regexp{gpgRegExp}},
//	"gpg-agent":                            {"gnupg", "gnupg", []*regexp.Regexp{gpgagentRegExp}},
//	"vim":                                  {"vim", "vim", []*regexp.Regexp{vimRegExp, vimRegExp2}},
//	"gs":                                   {"ghostscript", "ghostscript", []*regexp.Regexp{gsRegExp}},
//	"gocr":                                 {"optical_character_recognition_utility", "gocr", []*regexp.Regexp{gocrRegExp}},
//	"pdftops":                              {"poppler", "poppler", []*regexp.Regexp{pdftopsRegExp}},
//	"ncftp":                                {"ncftp", "ncftp_software", []*regexp.Regexp{ncftpRegExp}},
//	"version":                              {"linux_kernel", "version", []*regexp.Regexp{versionRegExp, versionRegExp2}},
//	"gimp":                                 {"gimp", "gimp", []*regexp.Regexp{gimpRegExp}},
//	"toc2cue":                              {"cdrdao", "andreas_mueller", []*regexp.Regexp{toc2cueRegExp}},
//	"toc2cddb":                             {"cdrdao", "andreas_mueller", []*regexp.Regexp{toc2cddbRegExp}},
//	"isodebug":                             {"cdrecord", "cdrtools", []*regexp.Regexp{isodebugRegExp}},
//	"scgcheck":                             {"cdrecord", "cdrtools", []*regexp.Regexp{scgcheckRegExp}},
//	"devdump":                              {"cdrecord", "cdrtools", []*regexp.Regexp{devdumpRegExp}},
//	"isodump":                              {"cdrecord", "cdrtools", []*regexp.Regexp{isodumpRegExp}},
//	"isovfy":                               {"cdrecord", "cdrtools", []*regexp.Regexp{isovfyRegExp}},
//	"kbxutil":                              {"gnupg", "gnupg", []*regexp.Regexp{kbxutilRegExp}},
//	"watchgnupg":                           {"gnupg", "gnupg", []*regexp.Regexp{watchgnupgRegExp}},
//	"gpgsm":                                {"gnupg", "gnupg", []*regexp.Regexp{gpgsmRegExp}},
//	"gpgconf":                              {"gnupg", "gnupg", []*regexp.Regexp{gpgconfRegExp}},
//	"pinentry":                             {"app-crypt_pinentry", "gentoo", []*regexp.Regexp{pinentryRegExp}},
//	"qemu":                                 {"qemu", "qemu", []*regexp.Regexp{qemuRegExp}},
//	"eix":                                  {"linux_eix", "gentoo", []*regexp.Regexp{eixRegExp, eixRegExp2}},
//	"dvipng":                               {"dvipng", "jan_ake-larsson", []*regexp.Regexp{dvipngRegExp}},
//	"dvigif":                               {"dvipng", "jan_ake-larsson", []*regexp.Regexp{dvigifRegExp}},
//	"pdfto":                                {"poppler", "poppler", []*regexp.Regexp{pdftoRegExp}},
//	"apr":                                  {"apr", "apache", []*regexp.Regexp{aprRegExp}},
//	"apu":                                  {"apr-util", "apache", []*regexp.Regexp{apuRegExp}},
//	"saslauthd":                            {"cyrus-sasl", "carnegie_mellon_university", []*regexp.Regexp{saslauthdRegExp}},
//	"bzcat":                                {"bzip", "bzip2", []*regexp.Regexp{bzcatRegExp}},
//	"bunzip2":                              {"bzip", "bzip2", []*regexp.Regexp{bunzip2RegExp}},
//	"bzip2recover":                         {"bzip", "bzip2", []*regexp.Regexp{bzip2recoverRegExp}},
//	"libbz2.so":                            {"bzip", "bzip2", []*regexp.Regexp{libbz2soRegExp}},
//	"unzip":                                {"unzip", "info-zip", []*regexp.Regexp{unzipRegExp}},
//	"isoinfo":                              {"cdrecord", "cdrtools", []*regexp.Regexp{isoinfoRegExp, isoinfoRegExp2}},
//	"mkhybrid":                             {"cdrecord", "cdrtools", []*regexp.Regexp{mkhybridRegExp, mkhybridRegExp2}},
//	"gpg-connect-agent":                    {"gnupg", "gnupg", []*regexp.Regexp{gpgconnectagentRegExp}},
//	"symcryptrun":                          {"gnupg", "gnupg", []*regexp.Regexp{symcryptrunRegExp}},
//	"pdfinfo":                              {"poppler", "poppler", []*regexp.Regexp{pdfinfoRegExp}},
//	"pdfimages":                            {"poppler", "poppler", []*regexp.Regexp{pdfimagesRegExp}},
//	"pdffonts":                             {"poppler", "poppler", []*regexp.Regexp{pdffontsRegExp}},
//	"libpoppler":                           {"poppler", "poppler", []*regexp.Regexp{libpopplerRegExp}},
//	"libsqlite3":                           {"sqlite", "sqlite", []*regexp.Regexp{libsqlite3RegExp}},
//	"libperl.so":                           {"perl", "perl", []*regexp.Regexp{libperlsoRegExp, libperlsoRegExp2}},
//	"libpython":                            {"python", "python", []*regexp.Regexp{libpythonRegExp}},
//	"libapr-":                              {"apr-util", "apache", []*regexp.Regexp{libaprRegExp}},
//	"libaprutil-":                          {"apr-util", "apache", []*regexp.Regexp{libaprutilRegExp}},
//	"libsasl2.so":                          {"cyrus-sasl", "carnegie_mellon_university", []*regexp.Regexp{libsasl2soRegExp}},
//	"glib-gettextize":                      {"glib", "gnome", []*regexp.Regexp{glibgettextizeRegExp}},
//	"gmime-uu":                             {"gmime", "gnome", []*regexp.Regexp{gmimeuuRegExp}},
//	"gmime-config":                         {"gmime", "gnome", []*regexp.Regexp{gmimeconfigRegExp, gmimeconfigRegExp2}},
//	"libcdio-paranoia":                     {"libcdio", "gnu", []*regexp.Regexp{libcdioparanoiaRegExp}},
//	"mmc-tool":                             {"libcdio", "gnu", []*regexp.Regexp{mmctoolRegExp}},
//	"iso-read":                             {"libcdio", "gnu", []*regexp.Regexp{isoreadRegExp, isoreadRegExp2}},
//	"cd-info":                              {"libcdio", "gnu", []*regexp.Regexp{cdinfoRegExp, cdinfoRegExp2}},
//	"iso-info":                             {"libcdio", "gnu", []*regexp.Regexp{isoinfoRegExp, cddriveRegExp2}},
//	"cd-read":                              {"libcdio", "gnu", []*regexp.Regexp{cdreadRegExp}},
//	"cd-drive":                             {"libcdio", "gnu", []*regexp.Regexp{cddriveRegExp, cddriveRegExp2}},
//	"libcdio.so":                           {"libcdio", "gnu", []*regexp.Regexp{libcdiosoRegExp}},
//	"libssl.so":                            {"openssl", "openssl", []*regexp.Regexp{libsslsoRegExp}},
//	"libcrypto.so":                         {"openssl", "openssl", []*regexp.Regexp{libcryptosoRegExp}},
//	"unzz":                                 {"zziplib", "zziplib", []*regexp.Regexp{unzzRegExp}},
//	"zz":                                   {"zziplib", "zziplib", []*regexp.Regexp{zzRegExp}},
//	"strace":                               {"strace", "paul_kranenburg", []*regexp.Regexp{straceRegExp}},
//	"git":                                  {"git", "git", []*regexp.Regexp{gitRegExp}},
//	"svn":                                  {"subversion", "subversion", []*regexp.Regexp{svnRegExp}},
//	"libsvn":                               {"subversion", "subversion", []*regexp.Regexp{libsvnRegExp}},
//	"libkde":                               {"kdelibs", "kde", []*regexp.Regexp{libkdeRegExp}},
//	"mutt":                                 {"mutt", "mutt", []*regexp.Regexp{muttRegExp}},
//	"exiv2":                                {"exiv2", "andreas_huggel", []*regexp.Regexp{exiv2RegExp, exiv2RegExp2}},
//	"libasound.so":                         {"alsa-lib", "alsa", []*regexp.Regexp{libasoundsoRegExp}},
//	"libFLAC.so":                           {"libflac", "flac", []*regexp.Regexp{libFLACsoRegExp}},
//	"libgst":                               {"gst-plugins-base", "gstreamer", []*regexp.Regexp{libgstRegExp}},
//	"libpng":                               {"libpng", "libpng", []*regexp.Regexp{libpngRegExp, libpngRegExp2, libpngRegExp3, libpngRegExp4}},
//	"libsndfile.so":                        {"libsndfile", "gentoo", []*regexp.Regexp{libsndfilesoRegExp, libsndfilesoRegExp2}},
//	"zip":                                  {"zip", "info-zip", []*regexp.Regexp{zipRegExp}},
//	"rvi":                                  {"vim", "vim", []*regexp.Regexp{rviRegExp}},
//	"dbus-binding-tool":                    {"", "", []*regexp.Regexp{dbusbindingtoolRegExp}},
//	"xml2-config":                          {"libxml2", "xmlsoft", []*regexp.Regexp{xml2configRegExp}},
//	"xslt-config":                          {"libxslt", "xmlsoft", []*regexp.Regexp{xsltconfigRegExp}},
//	"libxslt.so.1.1.26":                    {"libxslt", "xmlsoft", []*regexp.Regexp{libxsltso1126RegExp}},
//	"unzip-mem":                            {"zziplib", "zziplib", []*regexp.Regexp{unzipmemRegExp}},
//	"libvorbis.so":                         {"libvorbis", "libvorbis", []*regexp.Regexp{libvorbissoRegExp, libvorbissoRegExp2, libvorbissoRegExp3}},
//	"swrast_dri.so":                        {"mesa", "brian_paul", []*regexp.Regexp{swrast_drisoRegExp}},
//	"libt1.so.5.1.2":                       {"t1lib", "t1lib", []*regexp.Regexp{libt1so512RegExp}},
//	"xine-list":                            {"xine-lib", "xine", []*regexp.Regexp{xinelistRegExp}},
//	"xineplug_inp_":                        {"xine-lib", "xine", []*regexp.Regexp{xineplug_inp_RegExp}},
//	"libxvidcore.so":                       {"xvid", "xvid", []*regexp.Regexp{libxvidcoresoRegExp}},
//	"vobStreamer":                          {"media_server", "live555", []*regexp.Regexp{vobStreamerRegExp}},
//	"testOnDemandRTSPServer":               {"media_server", "live555", []*regexp.Regexp{testOnDemandRTSPServerRegExp}},
//	"testMPEG1or2Splitter":                 {"media_server", "live555", []*regexp.Regexp{testMPEG1or2SplitterRegExp}},
//	"testMPEG4VideoToDarwin":               {"media_server", "live555", []*regexp.Regexp{testMPEG4VideoToDarwinRegExp}},
//	"MPEG2TransportStreamIndexer":          {"media_server", "live555", []*regexp.Regexp{MPEG2TransportStreamIndexerRegExp}},
//	"testMPEG4VideoStreamer":               {"media_server", "live555", []*regexp.Regexp{testMPEG4VideoStreamerRegExp}},
//	"testMPEG2TransportStreamTrickPlay":    {"media_server", "live555", []*regexp.Regexp{testMPEG2TransportStreamTrickPlayRegExp}},
//	"testMPEG1or2AudioVideoToDarwin":       {"media_server", "live555", []*regexp.Regexp{testMPEG1or2AudioVideoToDarwinRegExp}},
//	"testMPEG1or2ProgramToTransportStream": {"media_server", "live555", []*regexp.Regexp{testMPEG1or2ProgramToTransportStreamRegExp}},
//	"testWAVAudioStreamer":                 {"media_server", "live555", []*regexp.Regexp{testWAVAudioStreamerRegExp}},
//	"openRTSP":                             {"media_server", "live555", []*regexp.Regexp{openRTSPRegExp}},
//	"playSIP":                              {"media_server", "live555", []*regexp.Regexp{playSIPRegExp}},
//	"testAMRAudioStreamer":                 {"media_server", "live555", []*regexp.Regexp{testAMRAudioStreamerRegExp}},
//	"libliveMedia.so":                      {"media_server", "live555", []*regexp.Regexp{libliveMediasoRegExp}},
//	"libirc_proxy.so":                      {"", "", []*regexp.Regexp{libirc_proxysoRegExp}},
//	"dhcpcd":                               {"dhcpcd", "phystech", []*regexp.Regexp{dhcpcdRegExp}},
//	"vncviewer":                            {"tightvnc", "tightvnc", []*regexp.Regexp{vncviewerRegExp}},
//	"Xvnc":                                 {"tightvnc", "tightvnc", []*regexp.Regexp{XvncRegExp}},
//	"pan":                                  {"pan", "pan", []*regexp.Regexp{panRegExp}},
//	"cupsd":                                {"cups", "cups", []*regexp.Regexp{cupsdRegExp}},
//	"printers.cgi":                         {"cups", "cups", []*regexp.Regexp{printerscgiRegExp}},
//	"jobs.cgi":                             {"cups", "cups", []*regexp.Regexp{jobscgiRegExp}},
//	"classes.cgi":                          {"cups", "cups", []*regexp.Regexp{classescgiRegExp}},
//	"help.cgi":                             {"cups", "cups", []*regexp.Regexp{helpcgiRegExp}},
//	"admin.cgi":                            {"cups", "cups", []*regexp.Regexp{admincgiRegExp}},
//	"libcups.so":                           {"cups", "cups", []*regexp.Regexp{libcupssoRegExp, libcupssoRegExp2}},
//	"wpa_":                                 {"wpa_supplicant", "wpa_supplicant", []*regexp.Regexp{wpa_RegExp}},
//	"setfacl":                              {"acl", "xfs", []*regexp.Regexp{setfaclRegExp}},
//	"getfacl":                              {"acl", "xfs", []*regexp.Regexp{getfaclRegExp}},
//	"busybox":                              {"busybox", "busybox", []*regexp.Regexp{busyboxRegExp, busyboxRegExp2, busyboxRegExp3}},
//	"bb":                                   {"busybox", "busybox", []*regexp.Regexp{bbRegExp, bbRegExp2}},
//	"mdev":                                 {"busybox", "busybox", []*regexp.Regexp{mdevRegExp, mdevRegExp2}},
//	"dbus-":                                {"dbus", "freedesktop", []*regexp.Regexp{dbusRegExp, dbusRegExp2}},
//	"libdbus-":                             {"dbus", "freedesktop", []*regexp.Regexp{libdbusRegExp}},
//	"ed":                                   {"ed", "gnu", []*regexp.Regexp{edRegExp}},
//	"red":                                  {"ed", "gnu", []*regexp.Regexp{redRegExp}},
//	"eject":                                {"eject", "eject", []*regexp.Regexp{ejectRegExp}},
//	"find":                                 {"findutils", "gnu", []*regexp.Regexp{findRegExp}},
//	"oldfind":                              {"findutils", "gnu", []*regexp.Regexp{oldfindRegExp}},
//	"xargs":                                {"findutils", "gnu", []*regexp.Regexp{xargsRegExp}},
//	"grodvi":                               {"groff", "gnu", []*regexp.Regexp{grodviRegExp}},
//	"grolj4":                               {"groff", "gnu", []*regexp.Regexp{grolj4RegExp}},
//	"grotty":                               {"groff", "gnu", []*regexp.Regexp{grottyRegExp}},
//	"grolbp":                               {"groff", "gnu", []*regexp.Regexp{grolbpRegExp}},
//	"groff":                                {"groff", "gnu", []*regexp.Regexp{groffRegExp}},
//	"sandbox":                              {"sandbox", "sandbox", []*regexp.Regexp{sandboxRegExp}},
//	"libsandbox.so":                        {"sandbox", "sandbox", []*regexp.Regexp{libsandboxsoRegExp}},
//	"texindex":                             {"texinfo", "gnu", []*regexp.Regexp{texindexRegExp}},
//	"install-info":                         {"texinfo", "gnu", []*regexp.Regexp{installinfoRegExp}},
//	"infokey":                              {"texinfo", "gnu", []*regexp.Regexp{infokeyRegExp}},
//	"info":                                 {"texinfo", "gnu", []*regexp.Regexp{infoRegExp}},
//	"tunelp":                               {"util-linux", "linux", []*regexp.Regexp{tunelpRegExp, tunelpRegExp2}},
//	"fdformat":                             {"util-linux", "linux", []*regexp.Regexp{fdformatRegExp, fdformatRegExp2}},
//	"rtcwake":                              {"util-linux", "linux", []*regexp.Regexp{rtcwakeRegExp, rtcwakeRegExp2}},
//	"readprofile":                          {"util-linux", "linux", []*regexp.Regexp{readprofileRegExp, readprofileRegExp2}},
//	"ldattach":                             {"util-linux", "linux", []*regexp.Regexp{ldattachRegExp, ldattachRegExp2}},
//	"isosize":                              {"util-linux", "linux", []*regexp.Regexp{isosizeRegExp, isosizeRegExp2}},
//	"cal":                                  {"util-linux", "linux", []*regexp.Regexp{calRegExp, calRegExp2}},
//	"rename":                               {"util-linux", "linux", []*regexp.Regexp{renameRegExp, renameRegExp2}},
//	"chrt":                                 {"util-linux", "linux", []*regexp.Regexp{chrtRegExp, chrtRegExp2}},
//	"taskset":                              {"util-linux", "linux", []*regexp.Regexp{tasksetRegExp, tasksetRegExp2}},
//	"ddate":                                {"util-linux", "linux", []*regexp.Regexp{ddateRegExp, ddateRegExp2}},
//	"flock":                                {"util-linux", "linux", []*regexp.Regexp{flockRegExp, flockRegExp2}},
//	"script":                               {"util-linux", "linux", []*regexp.Regexp{scriptRegExp, scriptRegExp2}},
//	"renice":                               {"util-linux", "linux", []*regexp.Regexp{reniceRegExp, reniceRegExp2}},
//	"fdisk":                                {"util-linux", "linux", []*regexp.Regexp{fdiskRegExp, fdiskRegExp2}},
//	"fsck.minix":                           {"util-linux", "linux", []*regexp.Regexp{fsckminixRegExp, fsckminixRegExp2}},
//	"mkfs":                                 {"util-linux", "linux", []*regexp.Regexp{mkfsRegExp, mkfsRegExp2}},
//	"fsck":                                 {"util-linux", "linux", []*regexp.Regexp{fsckRegExp, fsckRegExp2}},
//	"sfdisk":                               {"util-linux", "linux", []*regexp.Regexp{sfdiskRegExp, sfdiskRegExp2}},
//	"blkid":                                {"util-linux", "linux", []*regexp.Regexp{blkidRegExp, blkidRegExp2}},
//	"mkswap":                               {"util-linux", "linux", []*regexp.Regexp{mkswapRegExp, mkswapRegExp2}},
//	"mkfs.minix":                           {"util-linux", "linux", []*regexp.Regexp{mkfsminixRegExp, mkfsminixRegExp2}},
//	"blockdev":                             {"util-linux", "linux", []*regexp.Regexp{blockdevRegExp, blockdevRegExp2}},
//	"swapoff":                              {"util-linux", "linux", []*regexp.Regexp{swapoffRegExp, swapoffRegExp2}},
//	"mkfs.bfs":                             {"util-linux", "linux", []*regexp.Regexp{mkfsbfsRegExp, mkfsbfsRegExp2}},
//	"mkfs.cramfs":                          {"util-linux", "linux", []*regexp.Regexp{mkfscramfsRegExp, mkfscramfsRegExp2}},
//	"cfdisk":                               {"util-linux", "linux", []*regexp.Regexp{cfdiskRegExp, cfdiskRegExp2}},
//	"hwclock":                              {"util-linux", "linux", []*regexp.Regexp{hwclockRegExp, hwclockRegExp2}},
//	"swapon":                               {"util-linux", "linux", []*regexp.Regexp{swaponRegExp, swaponRegExp2}},
//	"switch_root":                          {"util-linux", "linux", []*regexp.Regexp{switch_rootRegExp, switch_rootRegExp2}},
//	"grub-install":                         {"grub_legacy", "gnu", []*regexp.Regexp{grubinstallRegExp}},
//	"grub-set-default":                     {"grub_legacy", "gnu", []*regexp.Regexp{grubsetdefaultRegExp}},
//	"grub-terminfo":                        {"grub_legacy", "gnu", []*regexp.Regexp{grubterminfoRegExp}},
//	"grub":                                 {"grub_legacy", "gnu", []*regexp.Regexp{grubRegExp}},
//	"as":                                   {"binutils", "gnu", []*regexp.Regexp{asRegExp}},
//	"libbfd.so":                            {"binutils", "gnu", []*regexp.Regexp{libbfdsoRegExp}},
//	"libopcodes":                           {"binutils", "gnu", []*regexp.Regexp{libopcodesRegExp}},
//	"libbfd-":                              {"binutils", "gnu", []*regexp.Regexp{libbfdRegExp, libbfdRegExp2}},
//	"lex":                                  {"flex", "will_estes", []*regexp.Regexp{lexRegExp, lexRegExp2}},
//	"flex":                                 {"flex", "will_estes", []*regexp.Regexp{flexRegExp, flexRegExp2}},
//	"protoize":                             {"gcc", "gcc", []*regexp.Regexp{protoizeRegExp, protoizeRegExp2}},
//	"unprotoize":                           {"gcc", "gcc", []*regexp.Regexp{unprotoizeRegExp, unprotoizeRegExp2}},
//	"gdbserver":                            {"gdb", "gnu", []*regexp.Regexp{gdbserverRegExp}},
//	"gettext.sh":                           {"gettext", "gnu", []*regexp.Regexp{gettextshRegExp}},
//	"msgcat":                               {"gettext", "gnu", []*regexp.Regexp{msgcatRegExp}},
//	"ngettext":                             {"gettext", "gnu", []*regexp.Regexp{ngettextRegExp}},
//	"gettextize":                           {"gettext", "gnu", []*regexp.Regexp{gettextizeRegExp}},
//	"libgettext":                           {"gettext", "gnu", []*regexp.Regexp{libgettextRegExp}},
//	"m4":                                   {"m4", "gnu", []*regexp.Regexp{m4RegExp}},
//	"make":                                 {"make", "gnu", []*regexp.Regexp{makeRegExp}},
//	"gmake":                                {"make", "gnu", []*regexp.Regexp{gmakeRegExp}},
//	"lsattr":                               {"e2fsprogs", "ext2_filesystems_utilities", []*regexp.Regexp{lsattrRegExp}},
//	"chattr":                               {"e2fsprogs", "ext2_filesystems_utilities", []*regexp.Regexp{chattrRegExp}},
//	"libext2fs.so":                         {"e2fsprogs", "ext2_filesystems_utilities", []*regexp.Regexp{libext2fssoRegExp, libext2fssoRegExp2}},
//	"fsck.ext2":                            {"e2fsprogs", "ext2_filesystems_utilities", []*regexp.Regexp{fsckext2RegExp}},
//	"e2fsck":                               {"e2fsprogs", "ext2_filesystems_utilities", []*regexp.Regexp{e2fsckRegExp}},
//	"fsck.ext4dev":                         {"e2fsprogs", "ext2_filesystems_utilities", []*regexp.Regexp{fsckext4devRegExp}},
//	"e2image":                              {"e2fsprogs", "ext2_filesystems_utilities", []*regexp.Regexp{e2imageRegExp}},
//	"mkfs.ext3":                            {"e2fsprogs", "ext2_filesystems_utilities", []*regexp.Regexp{mkfsext3RegExp}},
//	"mke2fs":                               {"e2fsprogs", "ext2_filesystems_utilities", []*regexp.Regexp{mke2fsRegExp}},
//	"e2label":                              {"e2fsprogs", "ext2_filesystems_utilities", []*regexp.Regexp{e2labelRegExp}},
//	"dumpe2fs":                             {"e2fsprogs", "ext2_filesystems_utilities", []*regexp.Regexp{dumpe2fsRegExp}},
//	"fsck.ext4":                            {"e2fsprogs", "ext2_filesystems_utilities", []*regexp.Regexp{fsckext4RegExp}},
//	"tune2fs":                              {"e2fsprogs", "ext2_filesystems_utilities", []*regexp.Regexp{tune2fsRegExp}},
//	"debugfs":                              {"e2fsprogs", "ext2_filesystems_utilities", []*regexp.Regexp{debugfsRegExp}},
//	"mkfs.ext2":                            {"e2fsprogs", "ext2_filesystems_utilities", []*regexp.Regexp{mkfsext2RegExp}},
//	"fsck.ext3":                            {"e2fsprogs", "ext2_filesystems_utilities", []*regexp.Regexp{fsckext3RegExp}},
//	"mkfs.ext4dev":                         {"e2fsprogs", "ext2_filesystems_utilities", []*regexp.Regexp{mkfsext4devRegExp}},
//	"mkfs.ext4":                            {"e2fsprogs", "ext2_filesystems_utilities", []*regexp.Regexp{mkfsext4RegExp}},
//	"resize2fs":                            {"e2fsprogs", "ext2_filesystems_utilities", []*regexp.Regexp{resize2fsRegExp}},
//	"libfuse.so":                           {"fuse", "fuse", []*regexp.Regexp{libfusesoRegExp}},
//	"iconvconfig":                          {"glibc", "gnu", []*regexp.Regexp{iconvconfigRegExp}},
//	"rpcinfo":                              {"glibc", "gnu", []*regexp.Regexp{rpcinfoRegExp}},
//	"nscd":                                 {"glibc", "gnu", []*regexp.Regexp{nscdRegExp}},
//	"lddlibc4":                             {"glibc", "gnu", []*regexp.Regexp{lddlibc4RegExp}},
//	"iconv":                                {"glibc", "gnu", []*regexp.Regexp{iconvRegExp}},
//	"locale":                               {"glibc", "gnu", []*regexp.Regexp{localeRegExp}},
//	"rpcgen":                               {"glibc", "gnu", []*regexp.Regexp{rpcgenRegExp}},
//	"getconf":                              {"glibc", "gnu", []*regexp.Regexp{getconfRegExp}},
//	"getent":                               {"glibc", "gnu", []*regexp.Regexp{getentRegExp}},
//	"localedef":                            {"glibc", "gnu", []*regexp.Regexp{localedefRegExp}},
//	"sprof":                                {"glibc", "gnu", []*regexp.Regexp{sprofRegExp}},
//	"libthread_db":                         {"glibc", "gnu", []*regexp.Regexp{libthread_dbRegExp}},
//	"ldconfig":                             {"glibc", "gnu", []*regexp.Regexp{ldconfigRegExp}},
//	"libpthread.so":                        {"glibc", "gnu", []*regexp.Regexp{libpthreadsoRegExp}},
//	"libpthread-":                          {"glibc", "gnu", []*regexp.Regexp{libpthreadRegExp}},
//	"gencat":                               {"glibc", "gnu", []*regexp.Regexp{gencatRegExp}},
//	"pcprofiledump":                        {"glibc", "gnu", []*regexp.Regexp{pcprofiledumpRegExp}},
//	"sln":                                  {"glibc", "gnu", []*regexp.Regexp{slnRegExp}},
//	"pam_cracklib.so":                      {"pam", "pam", []*regexp.Regexp{pam_cracklibsoRegExp}},
//	"pam_xauth.so":                         {"pam", "pam", []*regexp.Regexp{pam_xauthsoRegExp}},
//	"libz.so":                              {"zlib", "gnu", []*regexp.Regexp{libzsoRegExp}},
//	"pango-":                               {"pango", "pango", []*regexp.Regexp{pangoRegExp}},
//	"libpango-":                            {"pango", "pango", []*regexp.Regexp{libpangoRegExp}},
//	"xscreensaver":                         {"xscreensaver", "xscreensaver", []*regexp.Regexp{xscreensaverRegExp}},
//	"id3v2":                                {"id3v2", "id3v2", []*regexp.Regexp{id3v2RegExp}},
//	"libid3":                               {"id3lib", "id3lib", []*regexp.Regexp{libid3RegExp}},
//	"id3info":                              {"id3lib", "id3lib", []*regexp.Regexp{id3infoRegExp}},
//	"id3cp":                                {"id3lib", "id3lib", []*regexp.Regexp{id3cpRegExp}},
//	"neon-config":                          {"neon", "webdav", []*regexp.Regexp{neonconfigRegExp}},
//	"transmission":                         {"transmission", "transmissionbt", []*regexp.Regexp{transmissionRegExp}},
//	"acpi":                                 {"acpi", "tim_hockin", []*regexp.Regexp{acpiRegExp}},
//	"libbrltty":                            {"brltty", "mielke", []*regexp.Regexp{libbrlttyRegExp}},
//	"cat":                                  {"coreutils", "gnu", []*regexp.Regexp{catRegExp}},
//	"chgrp":                                {"coreutils", "gnu", []*regexp.Regexp{chgrpRegExp}},
//	"chmod":                                {"coreutils", "gnu", []*regexp.Regexp{chmodRegExp}},
//	"chown":                                {"coreutils", "gnu", []*regexp.Regexp{chownRegExp}},
//	"cp":                                   {"coreutils", "gnu", []*regexp.Regexp{cpRegExp}},
//	"date":                                 {"coreutils", "gnu", []*regexp.Regexp{dateRegExp}},
//	"dd":                                   {"coreutils", "gnu", []*regexp.Regexp{ddRegExp}},
//	"dir":                                  {"coreutils", "gnu", []*regexp.Regexp{dirRegExp}},
//	"echo":                                 {"coreutils", "gnu", []*regexp.Regexp{echoRegExp}},
//	"false":                                {"coreutils", "gnu", []*regexp.Regexp{falseRegExp}},
//	"ln":                                   {"coreutils", "gnu", []*regexp.Regexp{lnRegExp}},
//	"ls":                                   {"coreutils", "gnu", []*regexp.Regexp{lsRegExp}},
//	"mkdir":                                {"coreutils", "gnu", []*regexp.Regexp{mkdirRegExp}},
//	"mknod":                                {"coreutils", "gnu", []*regexp.Regexp{mknodRegExp}},
//	"mv":                                   {"coreutils", "gnu", []*regexp.Regexp{mvRegExp}},
//	"pwd":                                  {"coreutils", "gnu", []*regexp.Regexp{pwdRegExp}},
//	"readlink":                             {"coreutils", "gnu", []*regexp.Regexp{readlinkRegExp}},
//	"rm":                                   {"coreutils", "gnu", []*regexp.Regexp{rmRegExp}},
//	"rmdir":                                {"coreutils", "gnu", []*regexp.Regexp{rmdirRegExp}},
//	"vdir":                                 {"coreutils", "gnu", []*regexp.Regexp{vdirRegExp}},
//	"sync":                                 {"coreutils", "gnu", []*regexp.Regexp{syncRegExp}},
//	"touch":                                {"coreutils", "gnu", []*regexp.Regexp{touchRegExp, touchRegExp2}},
//	"true":                                 {"coreutils", "gnu", []*regexp.Regexp{trueRegExp}},
//	"uname":                                {"coreutils", "gnu", []*regexp.Regexp{unameRegExp}},
//	"mktemp":                               {"coreutils", "gnu", []*regexp.Regexp{mktempRegExp}},
//	"install":                              {"coreutils", "gnu", []*regexp.Regexp{installRegExp}},
//	"hostid":                               {"coreutils", "gnu", []*regexp.Regexp{hostidRegExp}},
//	"nice":                                 {"coreutils", "gnu", []*regexp.Regexp{niceRegExp}},
//	"who":                                  {"coreutils", "gnu", []*regexp.Regexp{whoRegExp}},
//	"users":                                {"coreutils", "gnu", []*regexp.Regexp{usersRegExp}},
//	"pinky":                                {"coreutils", "gnu", []*regexp.Regexp{pinkyRegExp}},
//	"chcon":                                {"coreutils", "gnu", []*regexp.Regexp{chconRegExp}},
//	"dircolors":                            {"coreutils", "gnu", []*regexp.Regexp{dircolorsRegExp}},
//	"du":                                   {"coreutils", "gnu", []*regexp.Regexp{duRegExp}},
//	"link":                                 {"coreutils", "gnu", []*regexp.Regexp{linkRegExp}},
//	"mkfifo":                               {"coreutils", "gnu", []*regexp.Regexp{mkfifoRegExp}},
//	"nohup":                                {"coreutils", "gnu", []*regexp.Regexp{nohupRegExp}},
//	"shred":                                {"coreutils", "gnu", []*regexp.Regexp{shredRegExp}},
//	"stat":                                 {"coreutils", "gnu", []*regexp.Regexp{statRegExp}},
//	"unlink":                               {"coreutils", "gnu", []*regexp.Regexp{unlinkRegExp}},
//	"cksum":                                {"coreutils", "gnu", []*regexp.Regexp{cksumRegExp}},
//	"comm":                                 {"coreutils", "gnu", []*regexp.Regexp{commRegExp}},
//	"csplit":                               {"coreutils", "gnu", []*regexp.Regexp{csplitRegExp}},
//	"cut":                                  {"coreutils", "gnu", []*regexp.Regexp{cutRegExp}},
//	"expand":                               {"coreutils", "gnu", []*regexp.Regexp{expandRegExp}},
//	"fmt":                                  {"coreutils", "gnu", []*regexp.Regexp{fmtRegExp}},
//	"fold":                                 {"coreutils", "gnu", []*regexp.Regexp{foldRegExp}},
//	"head":                                 {"coreutils", "gnu", []*regexp.Regexp{headRegExp}},
//	"join":                                 {"coreutils", "gnu", []*regexp.Regexp{joinRegExp}},
//	"groups":                               {"coreutils", "gnu", []*regexp.Regexp{groupsRegExp}},
//	"md5sum":                               {"coreutils", "gnu", []*regexp.Regexp{md5sumRegExp}},
//	"nl":                                   {"coreutils", "gnu", []*regexp.Regexp{nlRegExp}},
//	"od":                                   {"coreutils", "gnu", []*regexp.Regexp{odRegExp}},
//	"paste":                                {"coreutils", "gnu", []*regexp.Regexp{pasteRegExp}},
//	"pr":                                   {"coreutils", "gnu", []*regexp.Regexp{prRegExp}},
//	"ptx":                                  {"coreutils", "gnu", []*regexp.Regexp{ptxRegExp}},
//	"sha1sum":                              {"coreutils", "gnu", []*regexp.Regexp{sha1sumRegExp}},
//	"sha224sum":                            {"coreutils", "gnu", []*regexp.Regexp{sha224sumRegExp}},
//	"sha256sum":                            {"coreutils", "gnu", []*regexp.Regexp{sha256sumRegExp}},
//	"sha384sum":                            {"coreutils", "gnu", []*regexp.Regexp{sha384sumRegExp}},
//	"sha512sum":                            {"coreutils", "gnu", []*regexp.Regexp{sha512sumRegExp}},
//	"shuf":                                 {"coreutils", "gnu", []*regexp.Regexp{shufRegExp}},
//	"split":                                {"coreutils", "gnu", []*regexp.Regexp{splitRegExp}},
//	"tac":                                  {"coreutils", "gnu", []*regexp.Regexp{tacRegExp}},
//	"tail":                                 {"coreutils", "gnu", []*regexp.Regexp{tailRegExp}},
//	"tr":                                   {"coreutils", "gnu", []*regexp.Regexp{trRegExp}},
//	"tsort":                                {"coreutils", "gnu", []*regexp.Regexp{tsortRegExp}},
//	"unexpand":                             {"coreutils", "gnu", []*regexp.Regexp{unexpandRegExp}},
//	"uniq":                                 {"coreutils", "gnu", []*regexp.Regexp{uniqRegExp}},
//	"wc":                                   {"coreutils", "gnu", []*regexp.Regexp{wcRegExp}},
//	"basename":                             {"coreutils", "gnu", []*regexp.Regexp{basenameRegExp}},
//	"env":                                  {"coreutils", "gnu", []*regexp.Regexp{envRegExp}},
//	"expr":                                 {"coreutils", "gnu", []*regexp.Regexp{exprRegExp}},
//	"factor":                               {"coreutils", "gnu", []*regexp.Regexp{factorRegExp}},
//	"id":                                   {"coreutils", "gnu", []*regexp.Regexp{idRegExp}},
//	"logname":                              {"coreutils", "gnu", []*regexp.Regexp{lognameRegExp}},
//	"pathchk":                              {"coreutils", "gnu", []*regexp.Regexp{pathchkRegExp}},
//	"printenv":                             {"coreutils", "gnu", []*regexp.Regexp{printenvRegExp}},
//	"printf":                               {"coreutils", "gnu", []*regexp.Regexp{printfRegExp}},
//	"runcon":                               {"coreutils", "gnu", []*regexp.Regexp{runconRegExp}},
//	"tee":                                  {"coreutils", "gnu", []*regexp.Regexp{teeRegExp}},
//	"truncate":                             {"coreutils", "gnu", []*regexp.Regexp{truncateRegExp}},
//	"tty":                                  {"coreutils", "gnu", []*regexp.Regexp{ttyRegExp}},
//	"whoami":                               {"coreutils", "gnu", []*regexp.Regexp{whoamiRegExp}},
//	"yes":                                  {"coreutils", "gnu", []*regexp.Regexp{yesRegExp}},
//	"base64":                               {"coreutils", "gnu", []*regexp.Regexp{base64RegExp}},
//	"arch":                                 {"coreutils", "gnu", []*regexp.Regexp{archRegExp}},
//	"chroot":                               {"coreutils", "gnu", []*regexp.Regexp{chrootRegExp}},
//	"mt-gnu":                               {"cpio", "gnu", []*regexp.Regexp{mtgnuRegExp}},
//	"libevolution":                         {"evolution", "gnome", []*regexp.Regexp{libevolutionRegExp}},
//	"evolution":                            {"evolution", "gnome", []*regexp.Regexp{evolutionRegExp}},
//	"gdb":                                  {"gdb", "gnu", []*regexp.Regexp{gdbRegExp}},
//	"gdm-binary":                           {"gdm", "gnome", []*regexp.Regexp{gdmbinaryRegExp}},
//	"gdmflexiserver":                       {"gdm", "gnome", []*regexp.Regexp{gdmflexiserverRegExp}},
//	"gpgsplit":                             {"gnupg", "gnupg", []*regexp.Regexp{gpgsplitRegExp}},
//	"gpg-zip":                              {"gnupg", "gnupg", []*regexp.Regexp{gpgzipRegExp}},
//	"hp-mkuri":                             {"hplip", "hp", []*regexp.Regexp{hpmkuriRegExp}},
//	"iptables":                             {"iptables", "netfilter_core_team", []*regexp.Regexp{iptablesRegExp, iptablesRegExp2}},
//	"ip6tables":                            {"iptables", "netfilter_core_team", []*regexp.Regexp{ip6tablesRegExp}},
//	"ip6tables-restore":                    {"iptables", "netfilter_core_team", []*regexp.Regexp{ip6tablesrestoreRegExp}},
//	"ip6tables-save":                       {"iptables", "netfilter_core_team", []*regexp.Regexp{ip6tablessaveRegExp}},
//	"lftp":                                 {"lftp", "alexander_v._lukyanov", []*regexp.Regexp{lftpRegExp}},
//	"ltrace":                               {"ltrace", "juan_cespedes", []*regexp.Regexp{ltraceRegExp}},
//	"libaudioscrobbler.so":                 {"rhythmbox", "gnome", []*regexp.Regexp{libaudioscrobblersoRegExp}},
//	"libdaap.so":                           {"rhythmbox", "gnome", []*regexp.Regexp{libdaapsoRegExp}},
//	"libmtpdevice.so":                      {"rhythmbox", "gnome", []*regexp.Regexp{libmtpdevicesoRegExp}},
//	"libfmradio.so":                        {"rhythmbox", "gnome", []*regexp.Regexp{libfmradiosoRegExp}},
//	"rhythmbox":                            {"rhythmbox", "gnome", []*regexp.Regexp{rhythmboxRegExp}},
//	"rsync":                                {"rsync", "samba", []*regexp.Regexp{rsyncRegExp}},
//	"imuxsock.so":                          {"rsyslog", "rsyslog", []*regexp.Regexp{imuxsocksoRegExp, imuxsocksoRegExp2}},
//	"ommail.so":                            {"rsyslogd", "rsyslog", []*regexp.Regexp{ommailsoRegExp, ommailsoRegExp2}},
//	"sudo":                                 {"sudo", "todd_miller", []*regexp.Regexp{sudoRegExp}},
//	"visudo":                               {"sudo", "todd_miller", []*regexp.Regexp{visudoRegExp}},
//	"vinagre":                              {"vinagre", "gnome", []*regexp.Regexp{vinagreRegExp}},
//	"w3m":                                  {"w3m", "w3m", []*regexp.Regexp{w3mRegExp}},
//	"xinput":                               {"xinput", "x.org", []*regexp.Regexp{xinputRegExp, xinputRegExp2}},
//	"xsane":                                {"xsane", "oliver_rauch", []*regexp.Regexp{xsaneRegExp}},
//	"xml":                                  {"command_line_xml_toolkit", "xmlstarlet", []*regexp.Regexp{xmlRegExp}},
//	"xmlstarlet":                           {"command_line_xml_toolkit", "xmlstarlet", []*regexp.Regexp{xmlstarletRegExp}},
//	"ndisasm":                              {"nasm", "nasm", []*regexp.Regexp{ndisasmRegExp, ndisasmRegExp2}},
//	"libtasn1.so":                          {"libtasn1", "free_software_foundation_inc", []*regexp.Regexp{libtasn1soRegExp}},
//	"asn1":                                 {"libtasn1", "free_software_foundation_inc", []*regexp.Regexp{asn1RegExp}},
//	"libgconf-2.so":                        {"gconf", "gnome", []*regexp.Regexp{libgconf2soRegExp}},
//	"gconftool-2":                          {"gconf", "gnome", []*regexp.Regexp{gconftool2RegExp}},
//	"gdm":                                  {"gdm", "gnome", []*regexp.Regexp{gdmRegExp}},
//	"libgtop-2.0.so":                       {"libgtop_daemon", "gnome", []*regexp.Regexp{libgtop20soRegExp, libgtop20soRegExp2}},
//	"formail":                              {"procmail", "procmail", []*regexp.Regexp{formailRegExp}},
//	"postalias":                            {"postfix", "postfix", []*regexp.Regexp{postaliasRegExp}},
//	"postcat":                              {"postfix", "postfix", []*regexp.Regexp{postcatRegExp}},
//	"postfix":                              {"postfix", "postfix", []*regexp.Regexp{postfixRegExp, postfixRegExp2}},
//	"postkick":                             {"postfix", "postfix", []*regexp.Regexp{postkickRegExp}},
//	"postlog":                              {"postfix", "postfix", []*regexp.Regexp{postlogRegExp}},
//	"postmap":                              {"postfix", "postfix", []*regexp.Regexp{postmapRegExp}},
//	"postmulti":                            {"postfix", "postfix", []*regexp.Regexp{postmultiRegExp}},
//	"postsuper":                            {"postfix", "postfix", []*regexp.Regexp{postsuperRegExp}},
//	"postdrop":                             {"postfix", "postfix", []*regexp.Regexp{postdropRegExp}},
//	"postqueue":                            {"postfix", "postfix", []*regexp.Regexp{postqueueRegExp}},
//	"faad":                                 {"faad", "audiocoding", []*regexp.Regexp{faadRegExp}},
//	"imlib2-config":                        {"imlib2", "enlightenment", []*regexp.Regexp{imlib2configRegExp}},
//	"xine":                                 {"xine-ui", "xine", []*regexp.Regexp{xineRegExp}},
//	"fbxine":                               {"xine-ui", "xine", []*regexp.Regexp{fbxineRegExp}},
//	"nfsstat":                              {"nfs-utils", "nfs", []*regexp.Regexp{nfsstatRegExp}},
//	"rpc.mountd":                           {"nfs-utils", "nfs", []*regexp.Regexp{rpcmountdRegExp}},
//	"showmount":                            {"nfs-utils", "nfs", []*regexp.Regexp{showmountRegExp}},
//	"rpc.statd":                            {"nfs-utils", "nfs", []*regexp.Regexp{rpcstatdRegExp}},
//	"irssi":                                {"irssi", "irssi", []*regexp.Regexp{irssiRegExp}},
//	"apt":                                  {"jdk", "sun", []*regexp.Regexp{aptRegExp, aptRegExp2}},
//	"idlj":                                 {"jdk", "sun", []*regexp.Regexp{idljRegExp, idljRegExp2}},
//	"keytool":                              {"jdk", "sun", []*regexp.Regexp{keytoolRegExp, keytoolRegExp2, keytoolRegExp3, keytoolRegExp4}},
//	"jarsigner":                            {"jdk", "sun", []*regexp.Regexp{jarsignerRegExp, jarsignerRegExp2}},
//	"policytool":                           {"jdk", "sun", []*regexp.Regexp{policytoolRegExp, policytoolRegExp2, policytoolRegExp3, policytoolRegExp4}},
//	"jar":                                  {"jdk", "sun", []*regexp.Regexp{jarRegExp, jarRegExp2}},
//	"xjc":                                  {"jdk", "sun", []*regexp.Regexp{xjcRegExp, xjcRegExp2}},
//	"schemagen":                            {"jdk", "sun", []*regexp.Regexp{schemagenRegExp, schemagenRegExp2}},
//	"wsgen":                                {"jdk", "sun", []*regexp.Regexp{wsgenRegExp, wsgenRegExp2}},
//	"wsimport":                             {"jdk", "sun", []*regexp.Regexp{wsimportRegExp, wsimportRegExp2}},
//	"appletviewer":                         {"jdk", "sun", []*regexp.Regexp{appletviewerRegExp, appletviewerRegExp2}},
//	"rmic":                                 {"jdk", "sun", []*regexp.Regexp{rmicRegExp, rmicRegExp2}},
//	"rmiregistry":                          {"jdk", "sun", []*regexp.Regexp{rmiregistryRegExp, rmiregistryRegExp2, rmiregistryRegExp3, rmiregistryRegExp4}},
//	"rmid":                                 {"jdk", "sun", []*regexp.Regexp{rmidRegExp, rmidRegExp2, rmidRegExp3, rmidRegExp4}},
//	"native2ascii":                         {"jdk", "sun", []*regexp.Regexp{native2asciiRegExp, native2asciiRegExp2}},
//	"serialver":                            {"jdk", "sun", []*regexp.Regexp{serialverRegExp, serialverRegExp2}},
//	"jps":                                  {"jdk", "sun", []*regexp.Regexp{jpsRegExp, jpsRegExp2}},
//	"jstat":                                {"jdk", "sun", []*regexp.Regexp{jstatRegExp, jstatRegExp2}},
//	"jstatd":                               {"jdk", "sun", []*regexp.Regexp{jstatdRegExp, jstatdRegExp2}},
//	"jsadebugd":                            {"jdk", "sun", []*regexp.Regexp{jsadebugdRegExp, jsadebugdRegExp2}},
//	"jstack":                               {"jdk", "sun", []*regexp.Regexp{jstackRegExp, jstackRegExp2}},
//	"jmap":                                 {"jdk", "sun", []*regexp.Regexp{jmapRegExp, jmapRegExp2}},
//	"jinfo":                                {"jdk", "sun", []*regexp.Regexp{jinfoRegExp, jinfoRegExp2}},
//	"jconsole":                             {"jdk", "sun", []*regexp.Regexp{jconsoleRegExp, jconsoleRegExp2}},
//	"jrunscript":                           {"jdk", "sun", []*regexp.Regexp{jrunscriptRegExp, jrunscriptRegExp2}},
//	"jhat":                                 {"jdk", "sun", []*regexp.Regexp{jhatRegExp, jhatRegExp2}},
//	"tnameserv":                            {"jdk", "sun", []*regexp.Regexp{tnameservRegExp, tnameservRegExp2, tnameservRegExp3, tnameservRegExp4}},
//	"orbd":                                 {"jdk", "sun", []*regexp.Regexp{orbdRegExp, orbdRegExp2, orbdRegExp3, orbdRegExp4}},
//	"servertool":                           {"jdk", "sun", []*regexp.Regexp{servertoolRegExp, servertoolRegExp2, servertoolRegExp3, servertoolRegExp4}},
//	"pack200":                              {"jdk", "sun", []*regexp.Regexp{pack200RegExp, pack200RegExp2, pack200RegExp3, pack200RegExp4}},
//	"extcheck":                             {"jdk", "sun", []*regexp.Regexp{extcheckRegExp, extcheckRegExp2}},
//	"jdb":                                  {"jdk", "sun", []*regexp.Regexp{jdbRegExp, jdbRegExp2}},
//	"java_vm":                              {"jdk", "sun", []*regexp.Regexp{java_vmRegExp, java_vmRegExp2}},
//	"libjava.so":                           {"jdk", "sun", []*regexp.Regexp{libjavasoRegExp, libjavasoRegExp2}},
//	"libjavaplugin_nscp_gcc29.so":          {"jdk", "sun", []*regexp.Regexp{libjavaplugin_nscp_gcc29soRegExp, libjavaplugin_nscp_gcc29soRegExp2}},
//	"mod_ssl.so":                           {"http_server", "apache", []*regexp.Regexp{mod_sslsoRegExp}},
//	"libvirtd":                             {"libvirt", "libvirt", []*regexp.Regexp{libvirtdRegExp}},
//	"libvirt.so":                           {"libvirt", "libvirt", []*regexp.Regexp{libvirtsoRegExp}},
//	"libvirt-qemu.so":                      {"libvirt", "libvirt", []*regexp.Regexp{libvirtqemusoRegExp}},
//	"dnsmasq":                              {"dnsmasq", "thekelleys", []*regexp.Regexp{dnsmasqRegExp}},
//	"gnutls":                               {"gnutls", "gnu", []*regexp.Regexp{gnutlsRegExp}},
//	"psktool":                              {"gnutls", "gnu", []*regexp.Regexp{psktoolRegExp}},
//	"srptool":                              {"gnutls", "gnu", []*regexp.Regexp{srptoolRegExp}},
//	"certtool":                             {"gnutls", "gnu", []*regexp.Regexp{certtoolRegExp}},
//	"libgnutls-extra.so":                   {"gnutls", "gnu", []*regexp.Regexp{libgnutlsextrasoRegExp}},
//	"libgnutls.so":                         {"gnutls", "gnu", []*regexp.Regexp{libgnutlssoRegExp}},
//	"makeinfo":                             {"texinfo", "gnu", []*regexp.Regexp{makeinfoRegExp}},
//	"libtool":                              {"libtool", "gnu", []*regexp.Regexp{libtoolRegExp}},
//	"links":                                {"links", "links", []*regexp.Regexp{linksRegExp, linksRegExp2}},
//	"_cairo.so":                            {"cairo", "redhat", []*regexp.Regexp{_cairosoRegExp}},
//	"resolve_stack_dump":                   {"mysql", "mysql", []*regexp.Regexp{resolve_stack_dumpRegExp}},
//	"mysql":                                {"mysql", "mysql", []*regexp.Regexp{mysqlRegExp, mysqlmariaRegExp}},
//	"libphp5.so":                           {"php", "php", []*regexp.Regexp{libphp5soRegExp}},
//	"php":                                  {"php", "php", []*regexp.Regexp{phpRegExp}},
//	"libmcrypt.so":                         {"libmcrypt", "mcrypt", []*regexp.Regexp{libmcryptsoRegExp}},
//	"libmount.so":                          {"util-linux", "linux", []*regexp.Regexp{libmountsoRegExp}},
//	"libblkid.so":                          {"util-linux", "linux", []*regexp.Regexp{libblkidsoRegExp}},
//	"umount":                               {"util-linux", "linux", []*regexp.Regexp{umountRegExp}},
//	"mount":                                {"util-linux", "linux", []*regexp.Regexp{mountRegExp}},
//	"findmnt":                              {"util-linux", "linux", []*regexp.Regexp{findmntRegExp}},
//	"aureport":                             {"util-linux", "linux", []*regexp.Regexp{aureportRegExp}},
//	"ausearch":                             {"util-linux", "linux", []*regexp.Regexp{ausearchRegExp}},
//	"auditd":                               {"util-linux", "linux", []*regexp.Regexp{auditdRegExp}},
//	"auditctl":                             {"util-linux", "linux", []*regexp.Regexp{auditctlRegExp}},
//	"libmysqlclient_r.so":                  {"mysql", "mysql", []*regexp.Regexp{libmysqlclient_rsoRegExp}},
//	"libmysqlclient.so":                    {"mysql", "mysql", []*regexp.Regexp{libmysqlclientsoRegExp}},
//	"bsdcpio":                              {"libarchive", "freebsd", []*regexp.Regexp{bsdcpioRegExp}},
//	"bsdtar":                               {"libarchive", "freebsd", []*regexp.Regexp{bsdtarRegExp}},
//	"libarchive.so":                        {"libarchive", "freebsd", []*regexp.Regexp{libarchivesoRegExp}},
//	"named":                                {"bind", "isc", []*regexp.Regexp{namedRegExp}},
//	"libisc.so":                            {"bind", "isc", []*regexp.Regexp{libiscsoRegExp}},
//	"libisccfg.so":                         {"bind", "isc", []*regexp.Regexp{libisccfgsoRegExp}},
//	"libbind9.so":                          {"bind", "isc", []*regexp.Regexp{libbind9soRegExp}},
//	"liblwres.so":                          {"bind", "isc", []*regexp.Regexp{liblwressoRegExp}},
//	"courier-imapd":                        {"courier-imap", "double_precision_incorporated", []*regexp.Regexp{courierimapdRegExp}},
//	"newrole":                              {"policycoreutils", "redhat", []*regexp.Regexp{newroleRegExp}},
//	"secon":                                {"policycoreutils", "redhat", []*regexp.Regexp{seconRegExp}},
//	"lighttpd":                             {"lighttpd", "lighttpd", []*regexp.Regexp{lighttpdRegExp, lighttpdRegExp2}},
//	"mod_dirlisting.so":                    {"lighttpd", "lighttpd", []*regexp.Regexp{moddirlistingsoRegExp}},
//	"mod_cgi.so":                           {"lighttpd", "lighttpd", []*regexp.Regexp{mod_cgisoRegExp}},
//	"mod_scgi.so":                          {"lighttpd", "lighttpd", []*regexp.Regexp{mod_scgisoRegExp}},
//	"mod_fastcgi.so":                       {"lighttpd", "lighttpd", []*regexp.Regexp{mod_fastcgisoRegExp}},
//	"mod_ssi.so":                           {"lighttpd", "lighttpd", []*regexp.Regexp{mod_ssisoRegExp}},
//}

func getExecutableInfo(filename string, reader io.Reader) (string, string, string, error) {
	_, file := filepath.Split(filename)
	//check whether we have regex for this binary file or not. if yes then proceed to check regex patterns otherwise return empty
	if exeInfo, ok := ExesInfo[file]; ok {
		var scanner *bufio.Scanner
		//The default limit is bufio.MaxScanTokenSize which is 64KiB. at a time we can take 64KB data to buffer and check this data to match regex,
		// if regex is still not matched, then we have to get next 64KB data till we reach EOF. but if content is longer than 65536 chars, scanner is silently errored.
		// so on error case recreate the scanner and get next 64KB data and continue to check the regex
		buffer := make([]byte, bufio.MaxScanTokenSize)
		for scanner == nil || scanner.Err() == bufio.ErrTooLong {
			scanner = bufio.NewScanner(reader)
			scanner.Buffer(buffer, 0)
			//new buffer to write the string content till we cross ascii range <32 & >126. we reset this buffer on every loop
			b := bytes.NewBuffer(nil)
			//this bytes_scanned holds []bytes from Scan content.
			//We will iterate over []bytes,write string content to buffer till we cross ascii range <32 & >126. now, the output string is compared against the regexp pattern.we reset bytes_scanned on every loop
			var bytes_scanned []byte
			for scanner.Scan() {
				bytes_scanned = scanner.Bytes()
				for i := 0; i < len(bytes_scanned); i++ {
					c := bytes_scanned[i]
					if c >= 32 && c <= 126 {
						b.WriteByte(c)
					} else {
						if b.Len() >= MINIMUM_REGEX_LEN {
							line := b.String()
							for _, r := range exeInfo.Constraints.RegexMatch {
								regex, err := regexp.Compile(r)
								if err != nil {
									return "", "", "", errors.Wrapf(err, "failed compiling regex %s found for executable %s", r, file)
								}
								if regex.MatchString(line) {
									obj := regex.FindStringSubmatch(line)
									if len(obj) > 1 {
										cpe := fmt.Sprintf("cpe:/a:%s:%s:%s", exeInfo.Vendor, exeInfo.Package, obj[1])
										return file, obj[1], cpe, nil
									}
								}
							}
						}
						b.Reset()
					}
				}
			}
			bytes_scanned = []byte{}
		}
	}
	return "", "", "", nil
}

// getDockerVersion attempts to get the Docker version installed (if any)
// by executing the "docker version" command and parsing the output (we do not
// use the docker client library here because we want to keep the analyzer a
// simple static executable)
func (ctx *AnalyzerInput) getDockerVersion() (docker *aquatypes.ImageResource, err error) {
	cmd := exec.Command("docker", "version")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return docker, errors.Wrap(err, "failed piping into stdout")
	}
	if err = cmd.Start(); err != nil {
		return docker, errors.Wrap(err, "failed running 'docker version'")
	}

	var serverSection bool
	var version, edition string
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		if !serverSection && scanner.Text() == "Server:" {
			serverSection = true
		} else if serverSection {
			matches := dockerVerRegex.FindStringSubmatch(scanner.Text())
			if len(matches) == 2 {
				version = matches[1]
				editionM := dockerEditionRegex.FindStringSubmatch(version)
				if len(editionM) == 3 {
					version = strings.TrimSuffix(version, editionM[1])
					if editionM[2] == "c" {
						edition = "community"
					} else if editionM[2] == "e" {
						edition = "enterprise"
					}
				}
				// do not break here, we need to read everything so cmd.Wait()
				// properly closes the stdout pipe
			}
		}
	}

	if err = cmd.Wait(); err != nil {
		return docker, errors.Wrap(err, "failed waiting for command to finish")
	}

	cpe := fmt.Sprintf("cpe:/a:docker:docker:%s", version)
	if edition != "" {
		cpe = fmt.Sprintf("%s::~~%s~~~", cpe, edition)
	}

	return &aquatypes.ImageResource{
		Type:    aquatypes.ImageResourceType_EXECUTABLE,
		Name:    "docker",
		Cpe:     cpe,
		Version: version,
	}, nil
}
