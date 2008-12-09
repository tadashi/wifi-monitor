class AP:
   def __init__(self, channel, src_addr, dst_addr):
      self.ch = channel
      self.s = src_addr
      self.d = dst_addr

   
   def __repr__(self):
      return "AP(channel=%d, src_addr=%s, dst_addr=%s)" % (self.ch, self.s, self.d)
   
   def __getitem__(self, idx):
      if idx == 0:
         return self.ch
      elif idx == 1:
         return self.s
      elif idx == 2:
         return self.d

   def __setitem__(self, idx, val):
      if idx == 0:
          self.ch = val
      elif idx == 1:
          self.s = val
      elif idx == 2:
          self.d = val
   
   def __len__(self):
      return 3
