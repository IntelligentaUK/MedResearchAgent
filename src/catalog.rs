use crate::models::ResearchDomain;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JournalTier {
    Field,
    Mechanism,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResearchJournalSource {
    pub id: &'static str,
    pub name: &'static str,
    pub issns: &'static [&'static str],
    pub homepage: &'static str,
    pub documentation_url: &'static str,
    pub access_notes: &'static str,
    pub tier: JournalTier,
}

impl ResearchJournalSource {
    pub fn europe_pmc_filter(&self) -> String {
        let joined = self
            .issns
            .iter()
            .map(|issn| format!("ISSN:{issn}"))
            .collect::<Vec<_>>()
            .join(" OR ");
        format!("({joined})")
    }

    pub fn page_size(&self) -> usize {
        match self.tier {
            JournalTier::Field => FIELD_JOURNAL_PAGE_SIZE,
            JournalTier::Mechanism => MECHANISM_JOURNAL_PAGE_SIZE,
        }
    }
}

pub const FIELD_JOURNAL_PAGE_SIZE: usize = 3;
pub const MECHANISM_JOURNAL_PAGE_SIZE: usize = 2;
pub const WIDER_CORPUS_PAGE_SIZE: usize = 12;

pub struct ResearchSourceCatalog;

impl ResearchSourceCatalog {
    pub fn journals(domain: ResearchDomain) -> &'static [ResearchJournalSource] {
        match domain {
            ResearchDomain::Dementia => DEMENTIA_FIELD_JOURNALS,
            ResearchDomain::Cancer => CANCER_FIELD_JOURNALS,
        }
    }

    pub fn mechanism_journals(domain: ResearchDomain) -> &'static [ResearchJournalSource] {
        match domain {
            ResearchDomain::Dementia => DEMENTIA_MECHANISM_JOURNALS,
            ResearchDomain::Cancer => &[],
        }
    }

    pub fn all_journals(domain: ResearchDomain) -> Vec<&'static ResearchJournalSource> {
        Self::journals(domain)
            .iter()
            .chain(Self::mechanism_journals(domain).iter())
            .collect()
    }

    pub fn source(id: &str) -> Option<&'static ResearchJournalSource> {
        DEMENTIA_FIELD_JOURNALS
            .iter()
            .chain(DEMENTIA_MECHANISM_JOURNALS.iter())
            .chain(CANCER_FIELD_JOURNALS.iter())
            .find(|j| j.id == id)
    }

    pub fn maximum_records(domain: ResearchDomain) -> usize {
        Self::journals(domain).len() * FIELD_JOURNAL_PAGE_SIZE
            + Self::mechanism_journals(domain).len() * MECHANISM_JOURNAL_PAGE_SIZE
            + WIDER_CORPUS_PAGE_SIZE
    }
}

pub static DEMENTIA_FIELD_JOURNALS: &[ResearchJournalSource] = &[
    ResearchJournalSource {
        id: "alzheimers-research-therapy",
        name: "Alzheimer's Research & Therapy",
        issns: &["1758-9193"],
        homepage: "https://link.springer.com/journal/13195",
        documentation_url: "https://link.springer.com/journal/13195",
        access_notes: "Open-access journal. The agent retrieves eligible deposited full text through Europe PMC or PMC BioC and retains the article's licence.",
        tier: JournalTier::Field,
    },
    ResearchJournalSource {
        id: "alzheimers-dementia",
        name: "Alzheimer's & Dementia",
        issns: &["1552-5279", "1552-5260"],
        homepage: "https://alz-journals.onlinelibrary.wiley.com/journal/15525279",
        documentation_url: "https://alz-journals.onlinelibrary.wiley.com/hub/journal/15525279/homepage/productinformation.html",
        access_notes: "Open access from 1 January 2024. Earlier articles are checked individually; the journal's name or publication year alone does not establish full-text eligibility.",
        tier: JournalTier::Field,
    },
    ResearchJournalSource {
        id: "diagnosis-assessment-disease-monitoring",
        name: "Alzheimer's & Dementia: Diagnosis, Assessment & Disease Monitoring",
        issns: &["2352-8729"],
        homepage: "https://alz-journals.onlinelibrary.wiley.com/journal/23528729",
        documentation_url: "https://alz-journals.onlinelibrary.wiley.com/journal/23528729",
        access_notes: "Open-access journal. Structured full text is retrieved for articles available through the supported repositories; article licences are retained.",
        tier: JournalTier::Field,
    },
    ResearchJournalSource {
        id: "translational-research-clinical-interventions",
        name: "Alzheimer's & Dementia: Translational Research & Clinical Interventions",
        issns: &["2352-8737"],
        homepage: "https://alz-journals.onlinelibrary.wiley.com/journal/23528737",
        documentation_url: "https://alz-journals.onlinelibrary.wiley.com/journal/23528737",
        access_notes: "Open-access journal. Structured full text is retrieved for articles available through the supported repositories; article licences are retained.",
        tier: JournalTier::Field,
    },
    ResearchJournalSource {
        id: "behavior-socioeconomics-aging",
        name: "Alzheimer's & Dementia: Behavior & Socioeconomics of Aging",
        issns: &["2997-3805"],
        homepage: "https://alz-journals.onlinelibrary.wiley.com/journal/29973805",
        documentation_url: "https://alz-journals.onlinelibrary.wiley.com/journal/29973805",
        access_notes: "Open-access journal. Europe PMC indexing and eligible repository deposits may be incomplete; an empty repository search does not mean the publisher's articles are unavailable.",
        tier: JournalTier::Field,
    },
    ResearchJournalSource {
        id: "dementia-neuropsychologia",
        name: "Dementia & Neuropsychologia",
        issns: &["2764-4863", "1980-5764"],
        homepage: "https://www.scielo.br/j/dn/",
        documentation_url: "https://www.scielo.br/journal/dn/about/",
        access_notes: "Open access through SciELO. Both current online and historical print/linking ISSNs are searched. The agent retrieves eligible repository copies and retains each article's licence.",
        tier: JournalTier::Field,
    },
    ResearchJournalSource {
        id: "frontiers-aging-neuroscience",
        name: "Frontiers in Aging Neuroscience",
        issns: &["1663-4365"],
        homepage: "https://www.frontiersin.org/journals/aging-neuroscience",
        documentation_url: "https://www.frontiersin.org/journals/aging-neuroscience/about",
        access_notes: "Open-access journal with a CC BY publishing policy. The agent retrieves eligible deposited full text and preserves the article-level licence and attribution.",
        tier: JournalTier::Field,
    },
    ResearchJournalSource {
        id: "bmc-geriatrics",
        name: "BMC Geriatrics",
        issns: &["1471-2318"],
        homepage: "https://link.springer.com/journal/12877",
        documentation_url: "https://link.springer.com/journal/12877",
        access_notes: "Open-access journal. Searches remain tied to the research objective because this journal covers older-adult health beyond dementia. Eligible repository full text is retrieved automatically.",
        tier: JournalTier::Field,
    },
];

pub static DEMENTIA_MECHANISM_JOURNALS: &[ResearchJournalSource] = &[
    ResearchJournalSource {
        id: "journal-of-neuroinflammation",
        name: "Journal of Neuroinflammation",
        issns: &["1742-2094"],
        homepage: "https://link.springer.com/journal/12974",
        documentation_url: "https://link.springer.com/journal/12974/how-to-publish-with-us",
        access_notes: "Open-access journal (Springer Nature / BMC). Searched for mechanism evidence with the research question's own terms; the journal is not dementia-specific. Eligible deposited bodies are retrieved through Europe PMC or PMC BioC, and article licences, including CC BY and non-commercial variants, are retained.",
        tier: JournalTier::Mechanism,
    },
    ResearchJournalSource {
        id: "molecular-neurodegeneration",
        name: "Molecular Neurodegeneration",
        issns: &["1750-1326"],
        homepage: "https://link.springer.com/journal/13024",
        documentation_url: "https://link.springer.com/journal/13024/how-to-publish-with-us",
        access_notes: "Open-access journal (Springer Nature / BMC). Searched for mechanism evidence with the research question's own terms; the journal is not dementia-specific. Eligible deposited bodies are retrieved through Europe PMC or PMC BioC, and article licences, including CC BY and non-commercial variants, are retained.",
        tier: JournalTier::Mechanism,
    },
    ResearchJournalSource {
        id: "acta-neuropathologica-communications",
        name: "Acta Neuropathologica Communications",
        issns: &["2051-5960"],
        homepage: "https://link.springer.com/journal/40478",
        documentation_url: "https://link.springer.com/journal/40478/how-to-publish-with-us",
        access_notes: "Open-access journal (Springer Nature / BMC). Searched for mechanism evidence with the research question's own terms; the journal is not dementia-specific. Eligible deposited bodies are retrieved through Europe PMC or PMC BioC, and article licences, including CC BY and non-commercial variants, are retained.",
        tier: JournalTier::Mechanism,
    },
    ResearchJournalSource {
        id: "redox-biology",
        name: "Redox Biology",
        issns: &["2213-2317"],
        homepage: "https://www.sciencedirect.com/journal/redox-biology",
        documentation_url: "https://www.sciencedirect.com/journal/redox-biology/about/aims-and-scope",
        access_notes: "Open-access journal (Elsevier). Eligible deposited bodies are retrieved through Europe PMC or PMC BioC; article licences include CC BY and CC BY-NC-ND and are retained. The publisher site is not scraped.",
        tier: JournalTier::Mechanism,
    },
    ResearchJournalSource {
        id: "cell-communication-and-signaling",
        name: "Cell Communication and Signaling",
        issns: &["1478-811X"],
        homepage: "https://link.springer.com/journal/12964",
        documentation_url: "https://link.springer.com/journal/12964/how-to-publish-with-us",
        access_notes: "Open-access journal (Springer Nature / BMC). Searched for mechanism evidence with the research question's own terms; the journal is not dementia-specific. Eligible deposited bodies are retrieved through Europe PMC or PMC BioC, and article licences, including CC BY and non-commercial variants, are retained.",
        tier: JournalTier::Mechanism,
    },
    ResearchJournalSource {
        id: "immunity-and-ageing",
        name: "Immunity & Ageing",
        issns: &["1742-4933"],
        homepage: "https://link.springer.com/journal/12979",
        documentation_url: "https://link.springer.com/journal/12979/how-to-publish-with-us",
        access_notes: "Open-access journal (Springer Nature / BMC). Searched for mechanism evidence with the research question's own terms; the journal is not dementia-specific. Eligible deposited bodies are retrieved through Europe PMC or PMC BioC, and article licences, including CC BY and non-commercial variants, are retained.",
        tier: JournalTier::Mechanism,
    },
    ResearchJournalSource {
        id: "gut-microbes",
        name: "Gut Microbes",
        issns: &["1949-0976", "1949-0984"],
        homepage: "https://www.tandfonline.com/journals/kgmi20",
        documentation_url: "https://www.tandfonline.com/action/journalInformation?journalCode=kgmi20",
        access_notes: "Open-access journal (Taylor & Francis). Print and electronic ISSNs are both searched. Eligible deposited bodies are retrieved through Europe PMC or PMC BioC; licences vary, including CC BY and non-commercial terms, and are retained.",
        tier: JournalTier::Mechanism,
    },
];

pub static CANCER_FIELD_JOURNALS: &[ResearchJournalSource] = &[
    ResearchJournalSource {
        id: "bmc-cancer",
        name: "BMC Cancer",
        issns: &["1471-2407"],
        homepage: "https://link.springer.com/journal/12885",
        documentation_url: "https://link.springer.com/journal/12885/how-to-publish-with-us",
        access_notes: "Open-access journal with no reader subscription or registration required. Article reuse terms vary, including CC BY and CC BY-NC-ND; the actual licence is retained. The agent retrieves eligible bodies through supported public routes.",
        tier: JournalTier::Field,
    },
    ResearchJournalSource {
        id: "breast-cancer-research",
        name: "Breast Cancer Research",
        issns: &["1465-542X"],
        homepage: "https://link.springer.com/journal/13058",
        documentation_url: "https://link.springer.com/journal/13058/how-to-publish-with-us",
        access_notes: "Open-access journal with no reader subscription or registration required. Article reuse terms vary, including CC BY and CC BY-NC-ND; the actual licence is retained. The agent retrieves eligible bodies through supported public routes.",
        tier: JournalTier::Field,
    },
    ResearchJournalSource {
        id: "cancer-cell-international",
        name: "Cancer Cell International",
        issns: &["1475-2867"],
        homepage: "https://link.springer.com/journal/12935",
        documentation_url: "https://link.springer.com/journal/12935/how-to-publish-with-us",
        access_notes: "Open-access journal with no reader subscription or registration required. Article reuse terms vary, including CC BY and CC BY-NC-ND; the actual licence is retained. The agent retrieves eligible bodies through supported public routes.",
        tier: JournalTier::Field,
    },
    ResearchJournalSource {
        id: "experimental-clinical-cancer-research",
        name: "Journal of Experimental & Clinical Cancer Research",
        issns: &["1756-9966"],
        homepage: "https://link.springer.com/journal/13046",
        documentation_url: "https://link.springer.com/journal/13046/how-to-publish-with-us",
        access_notes: "Open-access journal with no reader subscription or registration required. The publisher specifies CC BY article licensing and a CC0 data policy; the actual article and dataset terms are retained. The agent retrieves eligible bodies through supported public routes.",
        tier: JournalTier::Field,
    },
    ResearchJournalSource {
        id: "molecular-cancer",
        name: "Molecular Cancer",
        issns: &["1476-4598"],
        homepage: "https://link.springer.com/journal/12943",
        documentation_url: "https://link.springer.com/journal/12943/how-to-publish-with-us",
        access_notes: "Open-access journal with no reader subscription or registration required. Article reuse terms vary, including CC BY and CC BY-NC-ND; the actual licence is retained. The agent retrieves eligible bodies through supported public routes.",
        tier: JournalTier::Field,
    },
    ResearchJournalSource {
        id: "hematology-oncology",
        name: "Journal of Hematology & Oncology",
        issns: &["1756-8722"],
        homepage: "https://link.springer.com/journal/13045",
        documentation_url: "https://link.springer.com/journal/13045/how-to-publish-with-us",
        access_notes: "Open-access journal with no reader subscription or registration required. Article reuse terms vary, including CC BY and CC BY-NC-ND; the actual licence is retained. The agent retrieves eligible bodies through supported public routes.",
        tier: JournalTier::Field,
    },
    ResearchJournalSource {
        id: "frontiers-oncology",
        name: "Frontiers in Oncology",
        issns: &["2234-943X"],
        homepage: "https://www.frontiersin.org/journals/oncology",
        documentation_url: "https://www.frontiersin.org/journals/oncology/about",
        access_notes: "Open access with a CC BY publishing policy. Eligible article bodies are retrieved through supported public repositories and identified copies; the article's actual licence is retained.",
        tier: JournalTier::Field,
    },
    ResearchJournalSource {
        id: "immunotherapy-cancer",
        name: "Journal for ImmunoTherapy of Cancer",
        issns: &["2051-1426"],
        homepage: "https://jitc.bmj.com/",
        documentation_url: "https://jitc.bmj.com/pages/about",
        access_notes: "Open-access journal. Eligible deposited bodies are retrieved through Europe PMC or PMC BioC. BMJ licences vary, including CC BY and non-commercial terms; preserve each article's licence. Direct BMJ-site scraping is not used.",
        tier: JournalTier::Field,
    },
];
