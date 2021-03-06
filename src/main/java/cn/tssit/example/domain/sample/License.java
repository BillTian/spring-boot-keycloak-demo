/*
 * Copyright 2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package cn.tssit.example.domain.sample;

import org.hibernate.envers.Audited;

import javax.persistence.Entity;
import javax.persistence.ManyToMany;
import javax.persistence.Version;
import java.util.Set;

/**
 * Sample domain class.
 *
 * @author Philip Huegelmeyer
 */
@Audited
@Entity
public class License extends AbstractEntity {

  @Version
  public Integer version;

  public String name;
  @ManyToMany
  public Set<Country> laender;
}
