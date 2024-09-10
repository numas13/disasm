use crate::printer::PrinterExt;

#[derive(Clone, Default)]
pub struct Symbols {
    sorted: bool,
    list: Vec<(u64, String)>,
}

impl Symbols {
    pub fn push<S: Into<String>>(&mut self, address: u64, name: S) {
        self.sorted = false;
        self.list.push((address, name.into()));
    }

    pub fn as_slice(&self) -> &[(u64, String)] {
        &self.list
    }

    pub fn as_info(&mut self) -> SymbolsInfo {
        if !self.sorted {
            self.list.sort_by_key(|(addr, _)| *addr);
            self.sorted = true;
        }
        SymbolsInfo { list: &self.list }
    }
}

pub struct SymbolsInfo<'a> {
    list: &'a [(u64, String)],
}

impl PrinterExt for SymbolsInfo<'_> {
    fn get_symbol(&self, address: u64) -> Option<(u64, &str)> {
        let index = match self.list.binary_search_by_key(&address, |(addr, _)| *addr) {
            Ok(index) => index,
            Err(index) => index.checked_sub(1)?,
        };
        self.list
            .get(index)
            .map(|(addr, name)| (*addr, name.as_str()))
    }

    fn get_symbol_after(&self, address: u64) -> Option<(u64, &str)> {
        let symbol = match self.list.binary_search_by_key(&address, |(addr, _)| *addr) {
            Ok(index) => self
                .list
                .iter()
                .skip(index)
                .find(|(addr, _)| *addr != address),
            Err(index) => self.list.get(index),
        };
        symbol.map(|(addr, name)| (*addr, name.as_str()))
    }
}
